#!/usr/bin/env bash
# Subtle whoosh bed for the v20 novice tour (~90s).
# 11 scenes = 10 transitions. Pink-noise whooshes only; no music.
set -euo pipefail

OUT=/tmp/video-tour/audio
mkdir -p "$OUT"

gen_whoosh() {
  local out=$1
  local vol=$2
  ffmpeg -y -f lavfi -i "anoisesrc=duration=0.4:color=pink:amplitude=0.7" \
    -af "highpass=f=180,lowpass=f=2200,volume=$vol,afade=t=in:st=0:d=0.03,afade=t=out:st=0.10:d=0.30" \
    -c:a pcm_s16le -ar 44100 -ac 2 "$out" 2>&1 | tail -1
}

gen_whoosh "$OUT/w-normal.wav" 0.42
gen_whoosh "$OUT/w-strong.wav" 0.65   # landing → signup (into the app)
gen_whoosh "$OUT/w-soft.wav"   0.28   # settings → close (denouement)

# Silent bed for 92 seconds (covers the ~89.3s tour).
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=92" \
  -c:a pcm_s16le "$OUT/silence.wav" 2>&1 | tail -1

# Transition offsets in ms, from compose.sh `Offsets:` output.
T1=5767     # 1  → 2  landing → signup
T2=11600    # 2  → 3  signup → overview
T3=21733    # 3  → 4  overview → sessions
T4=34633    # 4  → 5  sessions → session
T5=45466    # 5  → 6  session → download
T6=49299    # 6  → 7  download → verify
T7=56232    # 7  → 8  verify → policies
T8=64965    # 8  → 9  policies → deployments
T9=72265    # 9  → 10 deployments → settings
T10=82098   # 10 → 11 settings → close

ffmpeg -y \
  -i "$OUT/silence.wav" \
  -i "$OUT/w-strong.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
  -i "$OUT/w-normal.wav" \
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
    [8]adelay=${T8}|${T8}[w8];
    [9]adelay=${T9}|${T9}[w9];
    [10]adelay=${T10}|${T10}[w10];
    [0][w1][w2][w3][w4][w5][w6][w7][w8][w9][w10]amix=inputs=11:duration=first:normalize=0[mix];
    [mix]loudnorm=I=-24:LRA=8:TP=-3.0[out]
  " \
  -map "[out]" -c:a aac -b:a 128k "$OUT/soundtrack-44s.aac" 2>&1 | tail -1

ls -lh "$OUT/soundtrack-44s.aac"
