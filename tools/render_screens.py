"""Снимки работы программы в оформлении консоли Windows."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SCREENS = ROOT / "var" / "screens"
OUT = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\vkr\figures")

CONSOLAS = Path(r"C:\Windows\Fonts\consola.ttf")
SEGOE = Path(r"C:\Windows\Fonts\segoeui.ttf")

WIDTH = 1180
TITLE_H = 32
PAD_X = 14
PAD_Y = 8
LINE_H = 24
FONT_SIZE = 17

BG = (12, 12, 12)
TITLE_BG = (32, 32, 32)
BORDER = (58, 58, 58)
TEXT = (204, 204, 204)
PROMPT = (201, 201, 201)
COMMAND = (242, 242, 242)
TITLE_TEXT = (191, 191, 191)

PROJECT = "PS C:\\Users\\idv1102\\Documents\\deepseek-harness\\default-workspace\\siem-enricher>"


def font(path: Path, size: int):
    try:
        return ImageFont.truetype(str(path), size)
    except OSError:
        return ImageFont.load_default()


def read_lines(name: str) -> list[str]:
    text = (SCREENS / name).read_text(encoding="utf-8-sig")
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def draw_window(rows: list[tuple[str, str]], filename: str) -> Path:
    body_h = LINE_H * len(rows) + PAD_Y * 2
    width, height = WIDTH, TITLE_H + body_h

    image = Image.new("RGBA", (width, height), BG + (255,))
    draw = ImageDraw.Draw(image)

    draw.rectangle([0, 0, width, TITLE_H], fill=TITLE_BG)
    draw.text((12, 8), "Windows PowerShell", font=font(SEGOE, 15), fill=TITLE_TEXT)

    for offset, glyph in ((110, "min"), (78, "max"), (46, "close")):
        x = width - offset
        y = TITLE_H // 2
        if glyph == "min":
            draw.line([(x - 6, y), (x + 6, y)], fill=TITLE_TEXT, width=2)
        elif glyph == "max":
            draw.rectangle([x - 6, y - 6, x + 6, y + 6], outline=TITLE_TEXT, width=2)
        else:
            draw.line([(x - 6, y - 6), (x + 6, y + 6)], fill=TITLE_TEXT, width=2)
            draw.line([(x - 6, y + 6), (x + 6, y - 6)], fill=TITLE_TEXT, width=2)

    mono = font(CONSOLAS, FONT_SIZE)
    y = TITLE_H + PAD_Y
    for kind, text in rows:
        if kind == "prompt":
            draw.text((PAD_X, y), text, font=mono, fill=PROMPT)
        elif kind == "command":
            draw.text((PAD_X, y), text, font=mono, fill=COMMAND)
        elif kind == "continue":
            draw.text((PAD_X, y), ">>", font=mono, fill=PROMPT)
            draw.text((PAD_X + 20, y), text, font=mono, fill=COMMAND)
        else:
            draw.text((PAD_X, y), text, font=mono, fill=TEXT)
        y += LINE_H

    mask = Image.new("L", (width, height), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, width - 1, height - 1], radius=8, fill=255)
    framed = Image.new("RGB", (width, height), (255, 255, 255))
    framed.paste(image, (0, 0), mask)

    border = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    ImageDraw.Draw(border).rounded_rectangle(
        [0, 0, width - 1, height - 1], radius=8, outline=BORDER, width=1
    )
    framed.paste(border, (0, 0), border)

    path = OUT / filename
    OUT.mkdir(parents=True, exist_ok=True)
    framed.save(path, "PNG")
    return path


def classify_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [("prompt", PROJECT + " python -m siem_enricher classify `")]
    for arguments in (
        '  --path "C:\\HR\\Зарплатная_ведомость_2025.xlsx" `',
        '  --path "C:\\Public\\Пресс_релиз.docx" `',
        '  --path "C:\\keys\\id_rsa" `',
        '  --path "C:\\Юридический\\Договор_поставки.docx"',
    ):
        rows.append(("continue", arguments))
    rows.extend(("output", line) for line in read_lines("classify.txt"))
    rows.append(("prompt", PROJECT))
    return rows


def event_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [("prompt", PROJECT + " type var\\demo\\enriched_event.json")]
    rows.extend(("output", line) for line in read_lines("event.txt"))
    rows.append(("prompt", PROJECT))
    return rows


def wazuh_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = [("prompt", PROJECT + " wsl docker exec siem-wazuh sh /tmp/proof.sh")]
    rows.extend(("output", line) for line in read_lines("wazuh.txt"))
    rows.append(("prompt", PROJECT))
    return rows


def main() -> int:
    for filename, rows in (
        ("screen_classify.png", classify_rows()),
        ("screen_event.png", event_rows()),
        ("screen_wazuh.png", wazuh_rows()),
    ):
        path = draw_window(rows, filename)
        with Image.open(path) as opened:
            print(f"{path.name}: {opened.size[0]}x{opened.size[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
