"""Что умеет генератор событий: сценарии и параметры."""

import pathlib
import re

text = pathlib.Path(
    r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher\tools\generate_sample_events.py"
).read_text(encoding="utf-8")

match = re.search(r'add_argument\(\s*"--scenario",\s*default="([^"]+)"', text)
print("сценарий по умолчанию:", match.group(1) if match else "?")

for name in ("mixed", "insider", "exfil", "benign", "ransomware", "hr", "public"):
    if f'"{name}"' in text:
        print("сценарий:", name)

start = text.find("def build_events")
print("---")
print(text[start:start + 600])
