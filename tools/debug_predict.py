"""Почему базовые предсказания не совпадают: отладка внутри контейнера."""

import sys
from pathlib import Path

sys.path.insert(0, "/app")
sys.path.insert(0, "/app/src")

import tools.train_from_labels as trainer
from transformers import AutoModelForSequenceClassification, AutoTokenizer

print("BASE_ARTIFACT:", trainer.BASE_ARTIFACT, trainer.BASE_ARTIFACT.exists())
print("encoder:", trainer.load_encoder_names(trainer.BASE_ARTIFACT)[:6])
print("карта:", list(trainer.load_category_map().items())[:3])

tokenizer = AutoTokenizer.from_pretrained(str(trainer.BASE_ARTIFACT), local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(str(trainer.BASE_ARTIFACT), local_files_only=True)
print("id2label:", model.config.id2label)

rows = [{"path": r"C:\Бухгалтерия\Договор_поставки_ООО_Ромашка.docx", "name": "Договор_поставки_ООО_Ромашка.docx", "level": "confidential"}]
print("предсказания:", trainer.predict_levels(model, tokenizer, rows, trainer.load_category_map()))
