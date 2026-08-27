#!/usr/bin/env bash
# Generate voice narration + mix with whoosh bed for the full-flow
# walkthrough (v16).
#
# Uses macOS `say` (Samantha voice, 175 wpm) — one clip per scene.
# Narration is written to MIRROR the on-screen action and burned-in
# captions. Voice reinforces what the eye reads.
#
# Requires macOS. Requires build-audio.sh to have run first (produces
# the whoosh bed at $OUT/soundtrack-44s.aac).
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

# ── Narration script — full flow for a new user ───────────────────
#
#   Scene 1 (landing):   agentvisorai.me — hero
#   Scene 2 (signin):    live login form-fill
#   Scene 3 (overview):  dashboard first-load, $31,840 tile
#   Scene 4 (sessions):  sessions list, blocked row highlighted
#   Scene 5 (session):   session detail, blocked $8,400 event
#   Scene 6 (download):  click Download receipt
#   Scene 7 (verify):    drop receipt into public verifier
#   Scene 8 (close):     CTA + URL
#
say -r 175 -v Samantha -o "$VOICE/s1.aiff" "A new user lands on Agent Visor A I."
say -r 175 -v Samantha -o "$VOICE/s2.aiff" "They sign in. Any email. Password demo."
say -r 175 -v Samantha -o "$VOICE/s3.aiff" "Thirty two sessions today. Seven blocked. Thirty one thousand, eight hundred forty dollars saved."
say -r 175 -v Samantha -o "$VOICE/s4.aiff" "One session was stopped before it did damage."
say -r 175 -v Samantha -o "$VOICE/s5.aiff" "An A I tried to spend eight thousand four hundred dollars. Agent Visor blocked it. Signed. Auditable."
say -r 175 -v Samantha -o "$VOICE/s6.aiff" "Download the receipt in one click."
say -r 175 -v Samantha -o "$VOICE/s7.aiff" "Drop it into the public verifier. Green tick. No account. No login."
say -r 175 -v Samantha -o "$VOICE/s8.aiff" "A I agents you can hand to an auditor. Try it live at agentvisor A I dot me."

# Process each aiff to a stereo 44.1kHz wav with mild compression
# and per-clip loudnorm to -18 LUFS (broadcast dialog standard).
for i in 1 2 3 4 5 6 7 8; do
  ffmpeg -y -i "$VOICE/s$i.aiff" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene start offsets in the composed video (from compose.sh output).
# We start each narration ~200-400ms into the scene so the visual
# establishes just before the voice speaks. Defaults below are
# approximate for the initial recording; if you re-record with
# significantly different durations, update these to match the
# actual `Offsets:` line printed by compose.sh.
D1=300      # scene 1 lead
D2=6567     # scene 2 (offset 6.367s + 0.2s lead)
D3=13134    # scene 3 (offset 12.934s + 0.2s lead)
D4=20467    # scene 4 (offset 20.267s + 0.2s lead)
D5=26734    # scene 5 (offset 26.534s + 0.2s lead)
D6=35967    # scene 6 (offset 35.767s + 0.2s lead)
D7=40700    # scene 7 (offset 40.500s + 0.2s lead)
D8=48433    # scene 8 (offset 48.233s + 0.2s lead)

# Silent base layer (52s covers the ~50s expected total).
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=52" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

# Voice bus: delay each scene's clip to its start offset, then sum
ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" -i "$VOICE/s2.wav" -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" -i "$VOICE/s5.wav" -i "$VOICE/s6.wav" \
  -i "$VOICE/s7.wav" -i "$VOICE/s8.wav" \
  -filter_complex "
    [1]adelay=${D1}|${D1}[v1];
    [2]adelay=${D2}|${D2}[v2];
    [3]adelay=${D3}|${D3}[v3];
    [4]adelay=${D4}|${D4}[v4];
    [5]adelay=${D5}|${D5}[v5];
    [6]adelay=${D6}|${D6}[v6];
    [7]adelay=${D7}|${D7}[v7];
    [8]adelay=${D8}|${D8}[v8];
    [0][v1][v2][v3][v4][v5][v6][v7][v8]amix=inputs=9:duration=first:normalize=0[voice]
  " \
  -map "[voice]" -c:a pcm_s16le "$OUT/voice-bus.wav" 2>&1 | tail -1

# Mix voice bus + whoosh bed + ambient pad if present.
# Whoosh bed: -6dB under voice. Pad: -3dB (already very quiet at
# -30 LUFS integrated). Voice stays clear on top of both.
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
    -map "[out]" -c:a aac -b:a 192k -t 52 "$OUT/narration-44s.aac" 2>&1 | tail -1
else
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -filter_complex "
      [1]volume=0.5[bed];
      [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 52 "$OUT/narration-44s.aac" 2>&1 | tail -1
fi

ls -lh "$OUT/narration-44s.aac"
