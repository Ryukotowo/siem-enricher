from pathlib import Path

path = Path(r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher\src\siem_enricher\config.py")
lines = path.read_text(encoding="utf-8").splitlines()
start = next(i for i, line in enumerate(lines) if line.startswith("class MlConfig"))
for index in range(start, start + 24):
    print(f"{index + 1}: {lines[index]}")
print("--- defaults ---")
for index, line in enumerate(lines, 1):
    if "artifact_path" in line or "labels_file" in line or "confidence_floor" in line:
        print(f"{index}: {line}")
