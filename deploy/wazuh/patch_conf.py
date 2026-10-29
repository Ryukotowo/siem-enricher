"""Вставка блока активного реагирования в ossec.conf с проверкой XML."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

CLOSING = "</ossec_config>"


def main() -> int:
    conf = Path(sys.argv[1])
    snippet = Path(sys.argv[2]).read_text(encoding="utf-8")

    text = conf.read_text(encoding="utf-8")
    if "<name>quarantine</name>" in text:
        print("блок уже присутствует")
    else:
        index = text.rfind(CLOSING)
        if index == -1:
            print("!! закрывающий тег не найден")
            return 1
        text = text[:index] + snippet + "\n" + text[index:]
        print("блок active-response вставлен")

    conf.write_text(text, encoding="utf-8")
    try:
        ET.parse(conf)
    except ET.ParseError as error:
        print(f"!! xml битый: {error}")
        return 1
    print("xml корректен")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
