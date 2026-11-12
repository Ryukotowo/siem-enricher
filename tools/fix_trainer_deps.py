"""Тренеру нужны те же ML-зависимости, что и сервису (sklearn для label_encoder)."""

from __future__ import annotations

from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "Dockerfile.trainer"

OLD = '''RUN pip install --no-cache-dir \\
        --extra-index-url https://download.pytorch.org/whl/cpu \\
        "torch==2.5.1+cpu" \\
    && pip install --no-cache-dir "transformers==4.46.3" "safetensors==0.4.5"'''

NEW = '''COPY requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements-ml.txt'''


def main() -> int:
    text = PATH.read_text(encoding="utf-8")
    if NEW in text:
        print("уже исправлено")
        return 0
    if OLD not in text:
        print("!! не найден блок установки")
        return 1
    PATH.write_text(text.replace(OLD, NEW, 1), encoding="utf-8")
    print("тренер ставит requirements-ml.txt (включая scikit-learn и joblib)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
