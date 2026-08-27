#!/usr/bin/env bash
# Compose narration + whoosh bed for v10.
#
# Narration uses macOS `say` with Samantha voice, one clip per scene,
# aligned to the scene-start offsets in the composed video.
set -euo pipefail

OUT=/tmp/video-v4/audio
VOICE="$OUT/voice"

# Scene start offsets in the final composed video (from compose.sh output):
#   s1=0, s2=4970, s3=9900, s4=13370, s5=21670, s6=31400, s7=39330
# We start each narration ~300ms into the scene so the visual establishes
# first, EXCEPT scene 1 which starts on the intro card (no establish
# needed — the card IS the narration).
D1=400
D2=5133
D3=10000
D4=13566
D5=21833
D6=31533
D7=39400

# Duck the whoosh bed under narration so voice stays clear.
# We use sidechain compression: whoosh signal ducked by voice signal.

# Silent bed for 44 seconds (safety base layer)
ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=44" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

# First, build the voice bus (all 7 delayed & mixed together)
ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" \
  -i "$VOICE/s2.wav" \
  -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" \
  -i "$VOICE/s5.wav" \
  -i "$VOICE/s6.wav" \
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
  -map "[voice]" -c:a pcm_s16le "$OUT/voice-bus.wav" 2>&1 | tail -2

# Now mix voice bus + whoosh bed, with the bed ducked
# The whooshes are already very quiet (-24 LUFS integrated) so they
# don't need aggressive ducking — a static -6dB attenuation is enough.
ffmpeg -y \
  -i "$OUT/voice-bus.wav" \
  -i "$OUT/soundtrack-44s.aac" \
  -filter_complex "
    [1]volume=0.5[bed];
    [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
    [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
  " \
  -map "[out]" -c:a aac -b:a 192k -t 44 "$OUT/narration-44s.aac" 2>&1 | tail -2

ls -lh "$OUT/narration-44s.aac"
