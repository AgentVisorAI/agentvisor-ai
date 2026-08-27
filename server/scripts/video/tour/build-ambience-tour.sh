#!/usr/bin/env bash
# Generate a very subtle ambient pad for under the narration.
#
# Design: two very quiet sine waves (C2=65Hz and C3=131Hz octave)
# with slow amplitude modulation. No harmonics, no rhythm, nothing
# that could sound "cheap" or age badly. Just presence.
#
# Volume: -30 to -34 LUFS integrated — below the whoosh bed AND
# far below the voice. Detectable only when you're paying attention.
set -euo pipefail

OUT=/tmp/video-tour/audio

# Two-octave sine drone, very quiet, with slow tremolo (0.15 Hz
# amplitude modulation = 6.7-second cycle) so it breathes rather
# than droning statically.
#
# Bandpass-filtered to remove any DC/subsonic and any high content.
# Fade in over 3s from silence (so scene 1 opens clean), fade out
# over 4s at the end (CTA breathe).
ffmpeg -y \
  -f lavfi -i "sine=frequency=65:duration=92" \
  -f lavfi -i "sine=frequency=131:duration=92" \
  -filter_complex "
    [0]volume=0.65[b1];
    [1]volume=0.40[b2];
    [b1][b2]amix=inputs=2:normalize=0[mix];
    [mix]lowpass=f=800,highpass=f=45,
         tremolo=f=0.15:d=0.35,
         afade=t=in:st=0:d=3.0,
         afade=t=out:st=87:d=4.0,
         volume=0.90
    [out]
  " \
  -map "[out]" -c:a pcm_s16le "$OUT/ambience-46s.wav" 2>&1 | tail -1

ls -lh "$OUT/ambience-46s.wav"
ffmpeg -y -i "$OUT/ambience-46s.wav" -af "loudnorm=print_format=summary:linear=false" -f null - 2>&1 | grep -E "Integrated|True Peak" | head -2
