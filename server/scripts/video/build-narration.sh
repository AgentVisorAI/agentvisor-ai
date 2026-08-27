#!/usr/bin/env bash
# Generate voice narration + mix with whoosh bed for the final cut.
#
# Uses macOS `say` (Samantha voice, 175 wpm) — one clip per scene.
# Narration is intentionally short and worded to MIRROR the on-screen
# card copy and burned-in captions. Voice reinforces what the eye
# reads; the two channels never say different things.
#
# Requires macOS. Requires build-audio.sh to have run first (produces
# the whoosh bed at $OUT/soundtrack-44s.aac).
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

# ── Narration script (aligned to card/caption copy) ───────────────
#
#   Scene 1: card = "AI agents make real decisions with real money"
#   Scene 2: card = "One wrong decision. $8,400 gone."
#   Scene 3: card = "Every decision: captured. enforced. signed."
#   Scene 4: caption = "32 sessions · 7 blocked · $31,840 saved."
#   Scene 5: caption = "Blocked at $8,400. Signed. Auditable."
#   Scene 6: caption = "Drop the receipt. Verified in the browser. No account."
#   Scene 7: card = "AI agents you can hand to an auditor. agentvisorai.me"
#
say -r 175 -v Samantha -o "$VOICE/s1.aiff" "A I agents make real decisions. With real money."
say -r 175 -v Samantha -o "$VOICE/s2.aiff" "One wrong decision. Eight thousand four hundred dollars, gone."
say -r 175 -v Samantha -o "$VOICE/s3.aiff" "Every decision. Captured. Enforced. Signed."
say -r 175 -v Samantha -o "$VOICE/s4.aiff" "Thirty two sessions today. Seven blocked. Thirty one thousand, eight hundred forty dollars saved."
say -r 175 -v Samantha -o "$VOICE/s5.aiff" "An A I tried to spend eight thousand four hundred dollars. Agent Visor blocked it. Signed. Auditable."
say -r 175 -v Samantha -o "$VOICE/s6.aiff" "Drop the receipt. Verified in the browser. No account needed."
say -r 175 -v Samantha -o "$VOICE/s7.aiff" "A I agents you can hand to an auditor. Agent Visor."

# Process each aiff to a stereo 44.1kHz wav with mild compression
# and per-clip loudnorm to -18 LUFS (broadcast dialog standard).
for i in 1 2 3 4 5 6 7; do
  ffmpeg -y -i "$VOICE/s$i.aiff" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene start offsets in the composed video (from compose.sh output).
# We start each narration ~200-400ms into the scene so the visual
# establishes just before the voice speaks.
D1=400
D2=5133
D3=10000
D4=13566
D5=21833
D6=31533
D7=39400

# Silent 44s base layer
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=44" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

# Voice bus: delay each scene's clip to its start offset, then sum
ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" -i "$VOICE/s2.wav" -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" -i "$VOICE/s5.wav" -i "$VOICE/s6.wav" \
  -i "$VOICE/s7.wav" \
  -filter_complex "
    [1]adelay=${D1}|${D1}[v1];
    [2]adelay=${D2}|${D2}[v2];
    [3]adelay=${D3}|${D3}[v3];
    [4]adelay=${D4}|${D4}[v4];
    [5]adelay=${D5}|${D5}[v5];
    [6]adelay=${D6}|${D6}[v6];
    [7]adelay=${D7}|${D7}[v7];
    [0][v1][v2][v3][v4][v5][v6][v7]amix=inputs=8:duration=first:normalize=0[voice]
  " \
  -map "[voice]" -c:a pcm_s16le "$OUT/voice-bus.wav" 2>&1 | tail -1

# Mix voice bus + whoosh bed. Bed is auto-attenuated -6dB so voice
# stays clear on top. Final loudnorm to -18 LUFS.
ffmpeg -y \
  -i "$OUT/voice-bus.wav" \
  -i "$OUT/soundtrack-44s.aac" \
  -filter_complex "
    [1]volume=0.5[bed];
    [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
    [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
  " \
  -map "[out]" -c:a aac -b:a 192k -t 44 "$OUT/narration-44s.aac" 2>&1 | tail -1

ls -lh "$OUT/narration-44s.aac"
