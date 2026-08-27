#!/usr/bin/env bash
# Narration for the v21 distilled mock (~30s). macOS `say`,
# Samantha at 175 wpm. Five lines, worded to mirror the on-screen
# cards and captions.
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

# Neural narration via edge-tts (en-US-AriaNeural). Each clip is
# synthesized, tail-trimmed, and its rate auto-bumped until it fits
# the scene window (see W* below) with margin, so narration can never
# overlap the next scene's line.
EDGE_TTS="${EDGE_TTS:-/tmp/tts-venv/bin/edge-tts}"
VOICE_ID="en-US-AriaNeural"

gen() {
  local out=$1; local window=$2; shift 2
  local text="$*"
  local d rate
  for rate in "+20%" "+25%" "+30%" "+35%" "+40%"; do
    "$EDGE_TTS" --voice "$VOICE_ID" --rate="$rate" --text "$text" \
      --write-media "$out.mp3" 2>/dev/null
    ffmpeg -y -i "$out.mp3" \
      -af "silenceremove=stop_periods=-1:stop_threshold=-45dB:stop_duration=0.25" \
      -c:a pcm_s16le -ar 44100 "$out.raw.wav" 2>/dev/null
    d=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$out.raw.wav")
    if awk "BEGIN{exit !($d <= $window)}"; then
      echo "  $(basename "$out"): ${d}s @ $rate (window ${window}s)"
      return 0
    fi
  done
  echo "  WARNING: $(basename "$out") ${d}s exceeds window ${window}s even at +40%"
}

gen "$VOICE/s1" 4.1 "An A I agent just paid a fake vendor eight thousand four hundred dollars."
gen "$VOICE/s2" 6.45 "Agent Visor watches every A I agent. Thirty one thousand, eight hundred forty dollars saved."
gen "$VOICE/s3" 6.7 "Here is the order it stopped: a vendor not on the approved list. Blocked before the money moved, and signed."
gen "$VOICE/s4" 6.35 "Anyone can verify the receipt. Green tick. No account."
gen "$VOICE/s5" 4.7 "A I agents you can hand to an auditor. agentvisor A I dot me."

for i in 1 2 3 4 5; do
  ffmpeg -y -i "$VOICE/s$i.raw.wav" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene starts + ~200ms lead, from compose.sh `Offsets:`.
D1=300
D2=4567
D3=10334
D4=17901
D5=24401

ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=32" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" -i "$VOICE/s2.wav" -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" -i "$VOICE/s5.wav" \
  -filter_complex "
    [1]adelay=${D1}|${D1}[v1];
    [2]adelay=${D2}|${D2}[v2];
    [3]adelay=${D3}|${D3}[v3];
    [4]adelay=${D4}|${D4}[v4];
    [5]adelay=${D5}|${D5}[v5];
    [0][v1][v2][v3][v4][v5]amix=inputs=6:duration=first:normalize=0[voice]
  " \
  -map "[voice]" -c:a pcm_s16le "$OUT/voice-bus.wav" 2>&1 | tail -1

if [ -f "$OUT/ambience-46s.wav" ]; then
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -i "$OUT/ambience-46s.wav" \
    -filter_complex "
      [1]volume=0.5[bed];
      [2]volume=0.7[pad];
      [0][bed][pad]amix=inputs=3:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 32 "$OUT/narration-44s.aac" 2>&1 | tail -1
else
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -filter_complex "
      [1]volume=0.5[bed];
      [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 32 "$OUT/narration-44s.aac" 2>&1 | tail -1
fi

ls -lh "$OUT/narration-44s.aac"
