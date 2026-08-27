#!/usr/bin/env bash
# Voice narration for the v20 novice tour (~90s). macOS `say`,
# Samantha at 175 wpm, one clip per scene, worded to MIRROR the
# on-screen action and burned-in captions.
set -euo pipefail

OUT=/tmp/video-tour/audio
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

gen "$VOICE/s1" 5.4 "This is Agent Visor A I: the control plane for A I agents that touch real money and real systems."
gen "$VOICE/s2" 5.5 "The problem: one wrong agent decision can cost thousands, with no way to prove what happened."
gen "$VOICE/s3" 6.4 "Agent Visor blocks bad actions before money moves, and proves it afterwards. Here is the complete flow, from zero."
gen "$VOICE/s4" 4.6 "A brand new user lands on Agent Visor A I."
gen "$VOICE/s5" 7.2 "They create a workspace. Company, email, password. That is the whole setup."
gen "$VOICE/s6" 4.9 "A brand new workspace. Zero sessions, zero deployments. Nothing to audit, yet."
gen "$VOICE/s7" 9.0 "One install command connects their first daemon. Agent Visor issues its signing key automatically."
gen "$VOICE/s8" 9.6 "And the first sessions stream in. Within minutes, the first save: eight thousand four hundred dollars, blocked."
gen "$VOICE/s9" 5.9 "One click isolates the blocked session."
gen "$VOICE/s10" 9.2 "Inside it: the A I tried to spend eight thousand four hundred dollars. Blocked. And every event is inspectable."
gen "$VOICE/s11" 6.35 "Share a verification link, or copy the raw receipt. One click each."
gen "$VOICE/s12" 2.8 "The receipt downloads in one click."
gen "$VOICE/s13" 5.6 "Drop it into the public verifier. Green tick. No account."
gen "$VOICE/s14" 7.6 "Starter policies come enabled on day one. Plain rules, enforced before the money moves."
gen "$VOICE/s15" 6.6 "A command palette jumps anywhere. Light or dark, your call."
gen "$VOICE/s16" 5.9 "Each deployment gets its own signing key and ingest token."
gen "$VOICE/s17" 15.0 "Members, A P I keys, single sign on, webhooks, audit log, billing. Everything an admin needs is self serve, from the very first day. That is day one: from an empty workspace to a signed, verifiable audit trail."
gen "$VOICE/s18" 4.55 "A I agents you can hand to an auditor. agentvisor A I dot me."

for i in $(seq 1 18); do
  ffmpeg -y -i "$VOICE/s$i.raw.wav" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene-start offsets + ~200ms lead, from compose.sh `Offsets:`.
D1=300
D2=6100
D3=11700
D4=18300
D5=23800
D6=29733
D7=35333
D8=43866
D9=53866
D10=60399
D11=69932
D12=76832
D13=79565
D14=85398
D15=92898
D16=99431
D17=105398
D18=120965

ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=140" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" \
  -i "$VOICE/s2.wav" \
  -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" \
  -i "$VOICE/s5.wav" \
  -i "$VOICE/s6.wav" \
  -i "$VOICE/s7.wav" \
  -i "$VOICE/s8.wav" \
  -i "$VOICE/s9.wav" \
  -i "$VOICE/s10.wav" \
  -i "$VOICE/s11.wav" \
  -i "$VOICE/s12.wav" \
  -i "$VOICE/s13.wav" \
  -i "$VOICE/s14.wav" \
  -i "$VOICE/s15.wav" \
  -i "$VOICE/s16.wav" \
  -i "$VOICE/s17.wav" \
  -i "$VOICE/s18.wav" \
  -filter_complex "
    [1]adelay=${D1}|${D1}[v1];
    [2]adelay=${D2}|${D2}[v2];
    [3]adelay=${D3}|${D3}[v3];
    [4]adelay=${D4}|${D4}[v4];
    [5]adelay=${D5}|${D5}[v5];
    [6]adelay=${D6}|${D6}[v6];
    [7]adelay=${D7}|${D7}[v7];
    [8]adelay=${D8}|${D8}[v8];
    [9]adelay=${D9}|${D9}[v9];
    [10]adelay=${D10}|${D10}[v10];
    [11]adelay=${D11}|${D11}[v11];
    [12]adelay=${D12}|${D12}[v12];
    [13]adelay=${D13}|${D13}[v13];
    [14]adelay=${D14}|${D14}[v14];
    [15]adelay=${D15}|${D15}[v15];
    [16]adelay=${D16}|${D16}[v16];
    [17]adelay=${D17}|${D17}[v17];
    [18]adelay=${D18}|${D18}[v18];
    [0][v1][v2][v3][v4][v5][v6][v7][v8][v9][v10][v11][v12][v13][v14][v15][v16][v17][v18]amix=inputs=19:duration=first:normalize=0[voice]
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
    -map "[out]" -c:a aac -b:a 192k -t 135 "$OUT/narration-44s.aac" 2>&1 | tail -1
else
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -filter_complex "
      [1]volume=0.5[bed];
      [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 135 "$OUT/narration-44s.aac" 2>&1 | tail -1
fi

ls -lh "$OUT/narration-44s.aac"
