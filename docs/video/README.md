# PagerLens tutorial video: build

One command builds the review cut of the tutorial video (narrated, captioned mp4) from `docs/VIDEO-SCRIPT.md` and the recorder
`record.spec.ts`:

```bash
docs/video/build.sh          # about 8 minutes; writes docs/video/out/pagerlens.mp4 and pagerlens.srt (git-ignored)
```

Everything is local: a throwaway Postgres (initdb, no Docker), the demo stand-in model `scripts/fake_llm.py`, PagerLens, the
recorder in real Google Chrome, Kokoro (local neural text to speech) and ffmpeg. Nothing is downloaded and no real credential is involved (the admin
password is random per run and never shown).

## What it does

1. `narration.py audio`: runs the shared Kokoro narrator (`videos/tts/narrate.py scenes narration.txt ... --pronounce pronounce.json
   --voice af_bella`) on `narration.txt`, the narration written for listening. The `## <scene> <voice>` headers pick the voice:
   scenes 1-2 af_bella, 3-4 am_michael, 5-6 af_heart, 7-8 am_eric, 9-12 af_sarah (one voice per topic, alternating female and male,
   one US accent). It writes one wav per scene and `narration.json` with the length and the per-sentence cues of every scene.
   The audio is reused when `narration.txt` and `pronounce.json` have not changed (`FORCE_TTS=1` speaks it again).
2. A private Playwright browsers directory under `$WORK` makes Playwright's video recorder use your ffmpeg (`FFMPEG`, default the
   one on PATH) instead of its own build; `npx playwright install` is not needed.
3. `stack.sh start`: fresh Postgres cluster (vector and pg_trgm), `migrate`, `seed`, stand-in model, `pagerlens serve`, on
   loopback ports `BASE_PORT+1` to `+3` (default 41401 to 41403). A fresh database for every build.
4. `record.spec.ts` (1920x1080, full pace, `PACE=1`): every scene is held for its narration plus 1.2 s, and the actions inside a
   scene are anchored to the sentence they illustrate (`b.at('text of the sentence')`; a sentence that is not in `narration.txt`
   fails the run, so the two cannot drift apart). Long sentences get gentle scrolling so no picture sits still. It writes `pagerlens-tutorial.webm` and `scenes.json` (scene start times).
5. `narration.py mux`: places each scene's audio at its recorded start (the video's time zero is read from the moment the title card
   disappears in the file, not from the end of the file: anchoring on the end was measured 0.83 s off on this machine, which put the
   voice that much behind the picture; the title card is kept, only the blank page before it is cut), encodes H.264 yuv420p + AAC with `+faststart`, writes
   the captions (`.srt`, also embedded as a soft subtitle track), then `narration.py check` verifies that every scene lasts at
   least its audio plus 0.7 s, that audio and video lengths agree, that the narration has no silence over 3.5 s except the
   deliberate `[pause]` gaps over on-screen waits, and that no picture is frozen for more than 10 s.

## Settings (environment)

| Variable | Default | Meaning |
|---|---|---|
| `PG_BIN` | on PATH | directory with `initdb`, `pg_ctl`, `psql` of a Postgres with the `vector` and `pg_trgm` extensions |
| `WORK` | `docs/video/out/work` | scratch (database, audio, logs) |
| `OUT_DIR` | `docs/video/out` | output folder |
| `NAME` | `pagerlens` | output base name |
| `BASE_PORT` | `41400` | first of four loopback ports |
| `DELIVER_DIR` | unset | also copy the mp4 and srt there |
| `PACE` | `1` | recorder pace; below 1 is for rehearsals only (the checks then fail on purpose) |
| `TTS_DIR` | `../../../videos/tts` from the project | folder with `narrate.py`, its `.venv` and the Kokoro models |
| `FORCE_TTS` | unset | speak the narration again even if unchanged |
| `FFMPEG` | `ffmpeg` on PATH | ffmpeg binary for Playwright's recorder |

Needs: the Kokoro narrator (`TTS_DIR`), Google Chrome, node and npm (the first run does `npm install` in `docs/video`), ffmpeg and
ffprobe with libx264, python3, and the project's `.venv` (`pip install -e ".[dev]"`).

## Tuning

`pace.json` holds a per-scene factor for the recorder's pauses (below 1 shortens them). The recorder warns when a beat inside a
scene starts late ("beat N is X s late"); lower that scene's factor. `narration.txt` is the single source of the spoken text (the script mirrors it in its narration column and section 3);
`pronounce.json` holds project respellings merged over the shared `videos/tts/pronounce.json` (captions keep the written form).
Edit them, run `build.sh` again.

Scene 11's editor segment is a drawn terminal card with real MCP calls (see section 4 of the script), not a capture of an
assistant's window. The narration is synthetic (review quality); replace it with a human voice for release.
