"""Ускорение инференса: inference_mode и кэш токенизации."""

from __future__ import annotations

import ast
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "ml" / "transformer_classifier.py"

OLD_INFER = '''    def _infer(self, texts: Sequence[str]) -> list[list[float]]:
        torch = self._torch
        encoded = self._tokenizer(
            list(texts),
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            padding=True,
        )
        encoded = {key: value.to(self.device) for key, value in encoded.items()}
        with torch.no_grad():
            logits = self._model(**encoded).logits
            probabilities = torch.softmax(logits, dim=-1).cpu().tolist()'''

NEW_INFER = '''    def _encode(self, text: str) -> list[int]:
        """Идентификаторы токенов с кэшем: повторные имена не токенизируются заново."""
        cached = self._encode_cache.get(text)
        if cached is not None:
            self._encode_cache.move_to_end(text)
            return cached
        ids = list(self._tokenizer(text, truncation=True, max_length=self.max_length)["input_ids"])
        self._encode_cache[text] = ids
        while len(self._encode_cache) > self.encode_cache_size:
            self._encode_cache.popitem(last=False)
        return ids

    def _infer(self, texts: Sequence[str]) -> list[list[float]]:
        torch = self._torch
        pad_id = self._tokenizer.pad_token_id
        if pad_id is None:
            pad_id = 0
        rows = [self._encode(str(text)) for text in texts]
        width = max(len(row) for row in rows)
        input_ids = [row + [pad_id] * (width - len(row)) for row in rows]
        attention = [1] * width
        masks = [[1] * len(row) + [0] * (width - len(row)) for row in rows]
        tensors = {
            "input_ids": torch.tensor(input_ids, device=self.device),
            "attention_mask": torch.tensor(masks, device=self.device),
        }
        with torch.inference_mode():
            logits = self._model(**tensors).logits
            probabilities = torch.softmax(logits, dim=-1).cpu().tolist()'''

INIT_OLD = "        self.text_template = text_template"
INIT_NEW = """        self.text_template = text_template
        self.encode_cache_size = 8192
        self._encode_cache: OrderedDict[str, list[int]] = OrderedDict()"""


def main() -> int:
    text = FILE.read_text(encoding="utf-8")
    if "inference_mode" in text:
        print("уже применено")
        return 0
    if OLD_INFER not in text:
        print("!! не найден блок _infer")
        return 1
    text = text.replace(OLD_INFER, NEW_INFER, 1)

    if INIT_OLD in text:
        text = text.replace(INIT_OLD, INIT_NEW, 1)
        print("кэш токенов добавлен в __init__")
    else:
        print("!! не найден __init__")

    if "from collections import OrderedDict" not in text:
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("from pathlib import"):
                lines.insert(index + 1, "from collections import OrderedDict")
                break
        text = "\n".join(lines) + "\n"
        print("добавлен импорт OrderedDict")

    FILE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print("синтаксис ок, inference_mode и кэш токенов применены")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
