#!/usr/bin/env bash
# Generate voice narration + mix with whoosh bed for the v17
# flow-with-30s-hook walkthrough (~35s target).
#
# Uses macOS `say` (Samantha voice, 175 wpm). Narration MIRRORS the
# on-screen cards and captions — voice reinforces what the eye reads.
#
# Requires macOS. Requires build-audio.sh to have run first (produces
# the whoosh bed at $OUT/soundtrack-44s.aac).
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

# ── Narration script — flow with problem hook (v17) ───────────────
#
#   Scene 1 (problem):   card = "One wrong decision. $8,400 gone."
#   Scene 2 (signin):    login click
#   Scene 3 (overview):  caption = "32 sessions · 7 blocked · $31,840 saved."
#   Scene 4 (session):   caption = "Blocked at $8,400. Signed. Auditable."
#   Scene 5 (download):  caption = "Downloadable. Portable. Provable."
#   Scene 6 (verify):    caption = "Drop the receipt. Verified in the browser. No account."
#   Scene 7 (close):     card = "AI agents you can hand to an auditor. agentvisorai.me"
#
say -r 175 -v Samantha -o "$VOICE/s1.aiff" "One wrong A I decision. Eight thousand four hundred dollars, gone."
say -r 175 -v Samantha -o "$VOICE/s2.aiff" "One line of code, and they sign in."
say -r 175 -v Samantha -o "$VOICE/s3.aiff" "Thirty two sessions today. Seven blocked. Thirty one thousand, eight hundred forty dollars saved."
say -r 175 -v Samantha -o "$VOICE/s4.aiff" "The blocked one. Signed. Auditable."
say -r 175 -v Samantha -o "$VOICE/s5.aiff" "Download the receipt."
say -r 175 -v Samantha -o "$VOICE/s6.aiff" "Drop it into the public verifier. Green tick."
say -r 175 -v Samantha -o "$VOICE/s7.aiff" "A I agents you can hand to an auditor. Try it live at agentvisor A I dot me."

for i in 1 2 3 4 5 6 7; do
  ffmpeg -y -i "$VOICE/s$i.aiff" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene start offsets — filled after first compose from `Offsets:`
# line printed by compose.sh. Each narration starts ~200ms into
# the scene so the visual establishes before the voice speaks.
D1=300      # scene 1 (problem hook)
D2=3367     # scene 2 (offset 3.167s + 0.2 lead)
D3=7100     # scene 3 (offset 6.900s + 0.2 lead)
D4=14000    # scene 4 (offset 13.800s + 0.2 lead)
D5=21733    # scene 5 (offset 21.533s + 0.2 lead)
D6=25066    # scene 6 (offset 24.866s + 0.2 lead)
D7=31699    # scene 7 (offset 31.499s + 0.2 lead)

# Silent base layer (40s covers the ~35s expected total).
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=40" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

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
    -map "[out]" -c:a aac -b:a 192k -t 40 "$OUT/narration-44s.aac" 2>&1 | tail -1
else
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -filter_complex "
      [1]volume=0.5[bed];
      [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 40 "$OUT/narration-44s.aac" 2>&1 | tail -1
fi

ls -lh "$OUT/narration-44s.aac"
