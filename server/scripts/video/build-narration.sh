#!/usr/bin/env bash
# Narration for the v21 distilled mock (~30s). macOS `say`,
# Samantha at 175 wpm. Five lines, worded to mirror the on-screen
# cards and captions.
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

say -r 175 -v Samantha -o "$VOICE/s1.aiff" "One wrong A I decision. Eight thousand four hundred dollars, gone."
say -r 175 -v Samantha -o "$VOICE/s2.aiff" "Agent Visor prevents this. Thirty one thousand, eight hundred forty dollars saved."
say -r 175 -v Samantha -o "$VOICE/s3.aiff" "Here is the one it stopped. Blocked at eight thousand four hundred dollars. Signed."
say -r 175 -v Samantha -o "$VOICE/s4.aiff" "Anyone can verify the receipt. Green tick. No account."
say -r 175 -v Samantha -o "$VOICE/s5.aiff" "A I agents you can hand to an auditor. agentvisor A I dot me."

for i in 1 2 3 4 5; do
  ffmpeg -y -i "$VOICE/s$i.aiff" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene starts + ~200ms lead, from compose.sh `Offsets:`.
D1=300
D2=4600
D3=11200
D4=18066
D5=24599

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
