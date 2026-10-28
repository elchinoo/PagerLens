#!/usr/bin/env python3
"""Narration and final-cut helper for the PagerLens tutorial video (see docs/video/README.md).

  narration.py audio <out_dir>             speak docs/video/narration.txt with Kokoro (videos/tts/narrate.py; the voice of every
                                           scene comes from its `## <scene> <voice>` header) into <out_dir>/scene-<id>.wav and
                                           <out_dir>/narration.json (length and per-sentence cues of every scene)
  narration.py check <out_dir> <scenes.json> <mp4>
                                           verify: every scene lasts at least its audio + 0.7 s, audio and video lengths agree,
                                           no silence over 3.5 s except the deliberate [pause] gaps of the narration, and no
                                           picture frozen for more than 10 s (exit code 1 on a failure)
  narration.py mux <out_dir> <webm> <scenes.json> <mp4> <srt>
                                           place each scene's audio at its recorded start, encode H.264 yuv420p + AAC with
                                           +faststart, and write the captions (.srt, also embedded as a soft subtitle track)

Needs ffmpeg and ffprobe; TTS_DIR (default <repo parent>/videos/tts) holds narrate.py, its .venv and the Kokoro models.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
import wave
from pathlib import Path

HERE = Path(__file__).resolve().parent
TTS_DIR = Path(os.environ.get("TTS_DIR", HERE.parents[2] / "videos" / "tts"))
DEFAULT_VOICE = "af_bella"
LEAD_IN = 0.2           # the narration of a scene starts this long after the scene starts (must match record.spec.ts)
RATE = 24000            # narrate.py writes 24 kHz mono 16-bit wav
MAX_SILENCE = 3.5
MAX_FROZEN = 10.0


def run(*cmd: str) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_pcm(path: Path) -> bytes:
    with wave.open(str(path), "rb") as w:
        assert w.getframerate() == RATE and w.getnchannels() == 1 and w.getsampwidth() == 2, w.getparams()
        return w.readframes(w.getnframes())


def write_wav(path: Path, pcm: bytes) -> None:
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(RATE); w.writeframes(pcm)


def cmd_audio(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    stamp = out / "narration.stamp"
    digest = hashlib.sha256(b"".join(p.read_bytes() for p in (HERE / "narration.txt", HERE / "pronounce.json"))).hexdigest()
    if stamp.exists() and stamp.read_text() == digest and (out / "narration.json").exists() and not os.environ.get("FORCE_TTS"):
        print("narration unchanged since the last build: reusing the audio (FORCE_TTS=1 to speak it again)")
        (out / "timing.json").write_text((out / "narration.json").read_text())
        return
    py, tool = TTS_DIR / ".venv" / "bin" / "python", TTS_DIR / "narrate.py"
    if not py.exists() or not tool.exists():
        sys.exit(f"Kokoro narrator not found in {TTS_DIR}: set TTS_DIR to the folder with narrate.py and its .venv")
    subprocess.run([str(py), str(tool), "scenes", str(HERE / "narration.txt"), str(out), "--pronounce", str(HERE / "pronounce.json"),
                    "--voice", DEFAULT_VOICE], check=True)
    stamp.write_text(digest)
    # keep the file name the rest of the build uses
    (out / "timing.json").write_text((out / "narration.json").read_text())


def srt_time(t: float) -> str:
    ms = int(round(max(0.0, t) * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


def caption_chunks(sent: str, limit: int = 88) -> list[str]:
    """Split a long sentence at clause boundaries into caption-sized pieces."""
    if len(sent) <= limit:
        return [sent]
    parts = re.split(r"(?<=[,:;])\s+", sent)
    chunks, cur = [], ""
    for p in parts:
        if cur and len(cur) + 1 + len(p) > limit:
            chunks.append(cur); cur = p
        else:
            cur = (cur + " " + p).strip()
    if cur:
        chunks.append(cur)
    return chunks


def title_card_times(webm: Path):
    """(first, last) picture change of the first 12 s of the file: the title card appearing and being cleared (scene 0 is a 3.5 s card)."""
    out = subprocess.run(["ffmpeg", "-v", "info", "-t", "12", "-i", str(webm), "-vf", "select='gt(scene,0.05)',showinfo", "-an", "-f", "null", "-"],
                         capture_output=True, text=True).stderr
    t = [float(x) for x in re.findall(r"pts_time:([\d.]+)", out)]
    if len(t) < 2:
        return None, None
    appear = t[0]
    later = [x for x in t if x > appear + 2.0]
    return appear, (later[0] if later else None)


def cmd_mux(out: Path, webm: Path, scenes_json: Path, mp4: Path, srt: Path) -> None:
    timing = json.loads((out / "timing.json").read_text())
    rec = json.loads(scenes_json.read_text())
    vdur = float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(webm)]).strip())
    # The video's time zero (recorder clock at the first frame of the file). Anchoring it to the END of the file (closedAt - vdur) was
    # measured 0.83 s off on this machine (the file runs on after page.close() returns), which put the voice 0.8 s behind the picture.
    # So the clock is read from a picture event instead: the moment the title card disappears (scene 0 end, recorded by the recorder).
    zero_end = rec["closedAt"] - vdur
    appear, clear = title_card_times(webm)
    if clear is not None:
        zero = rec["scenes"]["0"]["end"] - clear
        print(f"video clock: title card seen at {appear:.2f} s and cleared at {clear:.2f} s of the file; end-anchored zero would be {zero_end - zero:+.2f} s off (corrected)")
    else:
        zero = zero_end
        print("WARNING: title card not found in the video, falling back to the end-anchored clock (can be ~0.8 s off)")
    # keep the title card: cut only the blank page before it
    trim = max(0.0, (appear if appear is not None else rec["scenes"]["0"]["start"] - zero) - 0.1)
    starts = {k: v["start"] - zero - trim for k, v in rec["scenes"].items() if k != "0"}
    vdur -= trim
    total = int(vdur * RATE) * 2
    track = bytearray(total)
    caps, idx = [], 1
    for k, s in sorted(starts.items(), key=lambda kv: int(kv[0])):
        pcm = read_pcm(out / f"scene-{k}.wav")
        a = int((s + LEAD_IN) * RATE) * 2
        track[a:a + len(pcm)] = pcm[:max(0, total - a)]
        for row in timing[k]["cues"]:
            chunks = caption_chunks(row["text"])
            span, total_chars, c0 = row["end"] - row["start"], sum(len(c) for c in chunks), row["start"]
            for c in chunks:
                c1 = c0 + span * len(c) / total_chars
                caps.append((idx, s + LEAD_IN + c0, s + LEAD_IN + c1, "\n".join(textwrap.wrap(c, 46))))
                idx += 1
                c0 = c1
    (out / "layout.json").write_text(json.dumps({k: v for k, v in starts.items()}))
    write_wav(out / "narration-full.wav", bytes(track))
    srt.write_text("".join(f"{i}\n{srt_time(a)} --> {srt_time(b - 0.04)}\n{t}\n\n" for i, a, b, t in caps), encoding="utf8")
    run("ffmpeg", "-y", "-ss", f"{trim:.3f}", "-i", str(webm), "-i", str(out / "narration-full.wav"), "-i", str(srt),
        "-map", "0:v", "-map", "1:a", "-map", "2:s", "-vf", "fps=30,scale=in_range=pc:out_range=tv,format=yuv420p", "-c:v", "libx264",
        "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "160k", "-ar", "48000", "-c:s", "mov_text",
        "-metadata:s:s:0", "language=eng", "-t", f"{vdur:.3f}", "-movflags", "+faststart", str(mp4))
    print(f"video {vdur:.1f} s, {len(caps)} captions -> {mp4}")


def cmd_check(out: Path, scenes_json: Path, mp4: Path) -> None:
    timing = json.loads((out / "timing.json").read_text())
    rec = json.loads(scenes_json.read_text())
    bad = 0
    for k, v in sorted(rec["scenes"].items(), key=lambda kv: int(kv[0])):
        if k == "0":
            continue
        length, need = v["end"] - v["start"], timing[k]["duration"] + 0.7
        flag = "ok " if length >= need else "SHORT"
        bad += length < need
        print(f"scene {int(k):2d} ({timing[k]['voice']}): {length:5.1f} s on screen, narration {timing[k]['duration']:5.1f} s (+0.7 = {need:5.1f})  {flag}")
    def dur(stream: str) -> float:
        return float(subprocess.check_output(["ffprobe", "-v", "error", "-select_streams", stream, "-show_entries", "stream=duration",
                                              "-of", "csv=p=0", str(mp4)]).split()[0])
    dv, da = dur("v:0"), dur("a:0")
    print(f"video {dv:.2f} s, audio {da:.2f} s")
    bad += abs(dv - da) > 0.5
    # silences: allowed only inside a deliberate [pause] (an inter-cue gap of the narration) or at the title card
    layout = json.loads((out / "layout.json").read_text())
    log = subprocess.run(["ffmpeg", "-i", str(mp4), "-af", f"silencedetect=noise=-45dB:d={MAX_SILENCE}", "-vn", "-f", "null", "-"],
                         capture_output=True, text=True).stderr
    found = [(float(a), float(b)) for a, b in re.findall(r"silence_start: ([0-9.]+)[\s\S]*?silence_duration: ([0-9.]+)", log)]
    gaps = []
    for k, st in layout.items():
        cues = timing[k]["cues"]
        gaps += [(st + LEAD_IN + a["end"], st + LEAD_IN + b["start"]) for a, b in zip(cues, cues[1:]) if b["start"] - a["end"] > 1.0]
    unexplained = [round(d, 1) for st, d in found if st >= 1.0 and not any(st >= g0 - 0.5 and st + d <= g1 + 0.5 for g0, g1 in gaps)]
    print(f"silences over {MAX_SILENCE} s: {[round(d, 1) for _, d in found] or 'none'}; outside a deliberate [pause]: {unexplained or 'none'}")
    bad += len(unexplained)
    fz = subprocess.run(["ffmpeg", "-i", str(mp4), "-vf", f"freezedetect=n=0.0003:d={MAX_FROZEN}", "-an", "-f", "null", "-"],
                        capture_output=True, text=True).stderr
    frozen = re.findall(r"freeze_duration: ([0-9.]+)", fz)
    print(f"picture frozen for more than {MAX_FROZEN:.0f} s:", frozen or "none")
    bad += len(frozen)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "audio":
        cmd_audio(Path(a[1]))
    elif len(a) == 4 and a[0] == "check":
        cmd_check(Path(a[1]), Path(a[2]), Path(a[3]))
    elif len(a) == 6 and a[0] == "mux":
        cmd_mux(Path(a[1]), Path(a[2]), Path(a[3]), Path(a[4]), Path(a[5]))
    else:
        sys.exit(__doc__)
