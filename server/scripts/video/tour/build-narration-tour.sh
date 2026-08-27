#!/usr/bin/env bash
# Voice narration for the v20 novice tour (~90s). macOS `say`,
# Samantha at 175 wpm, one clip per scene, worded to MIRROR the
# on-screen action and burned-in captions.
set -euo pipefail

OUT=/tmp/video-tour/audio
VOICE="$OUT/voice"
mkdir -p "$VOICE"

say -r 175 -v Samantha -o "$VOICE/s1.aiff"  "A brand new user lands on Agent Visor A I."
say -r 175 -v Samantha -o "$VOICE/s2.aiff"  "They create a workspace. Company, email, password. That is the whole setup."
say -r 175 -v Samantha -o "$VOICE/s3.aiff"  "First view: the dashboard. Thirty two sessions. Seven blocked. Thirty one thousand, eight hundred forty dollars saved."
say -r 175 -v Samantha -o "$VOICE/s4.aiff"  "Every session is searchable. One click isolates the blocked ones."
say -r 175 -v Samantha -o "$VOICE/s5.aiff"  "Inside a session, the A I tried to spend eight thousand four hundred dollars. Blocked. And every event is inspectable."
say -r 175 -v Samantha -o "$VOICE/s6.aiff"  "The receipt downloads in one click."
say -r 175 -v Samantha -o "$VOICE/s7.aiff"  "Drop it into the public verifier. Green tick. No account."
say -r 175 -v Samantha -o "$VOICE/s8.aiff"  "Policies are plain rules. Readable, and enforced before the money moves."
say -r 175 -v Samantha -o "$VOICE/s9.aiff"  "Each deployment gets its own signing key and ingest token."
say -r 175 -v Samantha -o "$VOICE/s10.aiff" "Teams, A P I keys, webhooks. The whole workspace is self serve."
say -r 175 -v Samantha -o "$VOICE/s11.aiff" "A I agents you can hand to an auditor. Try it live at agentvisor A I dot me."

for i in 1 2 3 4 5 6 7 8 9 10 11; do
  ffmpeg -y -i "$VOICE/s$i.aiff" \
    -af "aformat=sample_rates=44100:channel_layouts=stereo,highpass=f=100,acompressor=threshold=-20dB:ratio=3:attack=5:release=50,loudnorm=I=-18:LRA=6:TP=-2.0" \
    -c:a pcm_s16le "$VOICE/s$i.wav" 2>&1 | tail -1
done

# Scene-start offsets + ~200ms lead, from compose.sh `Offsets:`.
D1=300
D2=6167
D3=12000
D4=22133
D5=35033
D6=45866
D7=49699
D8=56632
D9=65365
D10=72665
D11=82498

ffmpeg -y -f lavfi -i "anullsrc=r=44100:cl=stereo:d=92" \
  -c:a pcm_s16le "$OUT/silence-44s.wav" 2>&1 | tail -1

ffmpeg -y \
  -i "$OUT/silence-44s.wav" \
  -i "$VOICE/s1.wav" -i "$VOICE/s2.wav" -i "$VOICE/s3.wav" \
  -i "$VOICE/s4.wav" -i "$VOICE/s5.wav" -i "$VOICE/s6.wav" \
  -i "$VOICE/s7.wav" -i "$VOICE/s8.wav" -i "$VOICE/s9.wav" \
  -i "$VOICE/s10.wav" -i "$VOICE/s11.wav" \
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
    [0][v1][v2][v3][v4][v5][v6][v7][v8][v9][v10][v11]amix=inputs=12:duration=first:normalize=0[voice]
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
    -map "[out]" -c:a aac -b:a 192k -t 92 "$OUT/narration-44s.aac" 2>&1 | tail -1
else
  ffmpeg -y \
    -i "$OUT/voice-bus.wav" \
    -i "$OUT/soundtrack-44s.aac" \
    -filter_complex "
      [1]volume=0.5[bed];
      [0][bed]amix=inputs=2:duration=longest:normalize=0[mix];
      [mix]loudnorm=I=-18:LRA=8:TP=-2.0[out]
    " \
    -map "[out]" -c:a aac -b:a 192k -t 92 "$OUT/narration-44s.aac" 2>&1 | tail -1
fi

ls -lh "$OUT/narration-44s.aac"
