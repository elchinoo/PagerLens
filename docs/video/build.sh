#!/usr/bin/env bash
# One command from docs/VIDEO-SCRIPT.md + docs/video/record.spec.ts to the finished tutorial video (mp4 with narration and
# captions). Everything is local: a throwaway Postgres, the demo stand-in model, the real recorder in real Chrome, Kokoro (local neural TTS).
#
#   docs/video/build.sh                      # -> docs/video/out/pagerlens.mp4 and docs/video/out/pagerlens.srt
#
# Environment (all optional except where the machine needs it):
#   PG_BIN      directory with initdb, pg_ctl and psql of a Postgres that has the vector and pg_trgm extensions
#               (not needed when they are already on PATH)
#   WORK        scratch directory for the database, audio, logs (default docs/video/out/work, git-ignored)
#   OUT_DIR     where the mp4, srt and the recorder files go (default docs/video/out)
#   NAME        output base name (default pagerlens)
#   BASE_PORT   first of four loopback ports used (default 41400: Postgres +1, stand-in model +2, PagerLens +3)
#   DELIVER_DIR if set, the mp4 and srt are also copied there
#   PACE        recorder pace multiplier (default 1 = full pace; below 1 only for rehearsals: scenes can then be shorter than
#               their narration and the checks fail)
#   FFMPEG      ffmpeg binary Playwright's video recorder should use (default: the one on PATH). Playwright's own build is
#               not downloaded: a private browsers directory under $WORK points its ffmpeg at this binary.
#   CAPTURES_DIR real captures from the live AgentPG fleet (extensions-installed.txt, ecoctl-insights.txt; default ../../../videos/live-captures)
#   TTS_DIR     folder with narrate.py (Kokoro), its .venv and models (default ../../../videos/tts relative to the project)
# Needs: Kokoro narrator (TTS_DIR), Google Chrome, node + npm, ffmpeg/ffprobe with libx264, python3, the project's .venv
# (`pip install -e ".[dev]"`). Re-running starts from a fresh database every time.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export WORK="${WORK:-$HERE/out/work}" BASE_PORT="${BASE_PORT:-41400}"
OUT_DIR="${OUT_DIR:-$HERE/out}"; NAME="${NAME:-pagerlens}"; PACE="${PACE:-1}"
FFMPEG="${FFMPEG:-$(command -v ffmpeg)}"
mkdir -p "$WORK" "$OUT_DIR"
for tool in ffmpeg ffprobe python3 node npm; do command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }; done
[ -x "$HERE/../../.venv/bin/pagerlens" ] || { echo "missing .venv: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'" >&2; exit 1; }
[ -d "$HERE/node_modules/@playwright" ] || (cd "$HERE" && npm install --no-audit --no-fund)

python3 -I "$HERE/narration.py" sync
echo "== 1/5 narration (Kokoro, voices from the headers of docs/video/narration.txt; about 2 minutes)"
python3 -I "$HERE/narration.py" audio "$WORK/narr"

echo "== 2/5 Playwright video support (private browsers dir, ffmpeg from $FFMPEG)"
REV="$(node -e "console.log(require('$HERE/node_modules/playwright-core/browsers.json').browsers.find(b=>b.name==='ffmpeg').revision)")"
export PLAYWRIGHT_BROWSERS_PATH="$WORK/pw-browsers"
mkdir -p "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$REV"
printf '#!/bin/sh\nexec "%s" "$@"\n' "$FFMPEG" > "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$REV/ffmpeg-mac"
chmod +x "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$REV/ffmpeg-mac"
touch "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$REV/INSTALLATION_COMPLETE" "$PLAYWRIGHT_BROWSERS_PATH/ffmpeg-$REV/DEPENDENCIES_VALIDATED"

echo "== 3/5 stack (fresh Postgres + stand-in model + PagerLens on ports $((BASE_PORT + 1))-$((BASE_PORT + 3)))"
trap '"$HERE/stack.sh" stop >/dev/null 2>&1 || true' EXIT
URL="$("$HERE/stack.sh" start)"

echo "== 4/5 recording (real Chrome, 1920x1080, PACE=$PACE; about 6 minutes)"
rm -f "$OUT_DIR/pagerlens-tutorial.webm" "$OUT_DIR/scenes.json"
PSQL_BIN="$(command -v psql)" PG_PORT=$((BASE_PORT + 1)) CAPTURES_DIR="${CAPTURES_DIR:-$HERE/../../../videos/live-captures}" \
ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')" \
PAGERLENS_URL="$URL" SETUP_LOG="$WORK/stack/app.log" PACE="$PACE" OUT_DIR="$OUT_DIR" \
NARRATION_TIMING="$WORK/narr/timing.json" PACE_FILE="$HERE/pace.json" \
  "$HERE/node_modules/.bin/playwright" test -c "$HERE/playwright.config.ts"
"$HERE/stack.sh" stop >/dev/null 2>&1 || true

echo "== 5/5 final cut (H.264 yuv420p + AAC, +faststart, captions)"
python3 -I "$HERE/narration.py" mux "$WORK/narr" "$OUT_DIR/pagerlens-tutorial.webm" "$OUT_DIR/scenes.json" "$OUT_DIR/$NAME.mp4" "$OUT_DIR/$NAME.srt"
python3 -I "$HERE/narration.py" check "$WORK/narr" "$OUT_DIR/scenes.json" "$OUT_DIR/$NAME.mp4"
if [ -n "${DELIVER_DIR:-}" ]; then mkdir -p "$DELIVER_DIR"; cp "$OUT_DIR/$NAME.mp4" "$OUT_DIR/$NAME.srt" "$DELIVER_DIR/"; echo "copied to $DELIVER_DIR"; fi
echo "done: $OUT_DIR/$NAME.mp4 ($(ffprobe -v error -show_entries format=duration -of csv=p=0 "$OUT_DIR/$NAME.mp4" | cut -d. -f1) s)"
