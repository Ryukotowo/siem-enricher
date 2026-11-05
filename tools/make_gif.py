"""Сборка GIF из кадров панели без подписей — для вставки в презентацию."""

from __future__ import annotations

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
FRAMES = ROOT / "var" / "gifs"
OUTPUT = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\vkr\figures\panel_stream.gif")

# пустой кадр не берём: в презентации первый кадр показывается как статичный
SKIP_FIRST = 1
WIDTH = 1300
DURATION = 900
HOLD_LAST = 1900


def main() -> int:
    files = sorted(FRAMES.glob("frame_*.png"))[SKIP_FIRST:]
    if not files:
        print("кадров нет")
        return 1

    images: list[Image.Image] = []
    for path in files:
        with Image.open(path) as source:
            frame = source.convert("RGB")
        ratio = WIDTH / frame.width
        images.append(frame.resize((WIDTH, int(frame.height * ratio)), Image.LANCZOS))

    durations = [DURATION] * (len(images) - 1) + [HOLD_LAST]
    frames = [image.convert("P", palette=Image.ADAPTIVE, colors=128) for image in images]

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"GIF без подписей: кадров {len(frames)}, {OUTPUT.stat().st_size / 1024:.0f} КБ")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
