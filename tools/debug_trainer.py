"""Диагностика тренера внутри контейнера."""

import sys
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, "/app/src")

from tools.train_from_labels import load_category_map, load_encoder_names

print("encoder:", load_encoder_names(Path("/app/ml/artifacts/sensitivity_transformer"))[:8])
mapping = load_category_map()
print("карта размером", len(mapping), "пример:", list(mapping.items())[:4])
