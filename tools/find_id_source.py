import pathlib

text = pathlib.Path(
    r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher\tools\generate_sample_events.py"
).read_text(encoding="utf-8")

for number, line in enumerate(text.splitlines(), 1):
    stripped = line.strip()
    if "1700000000" in stripped or 'event_id' in stripped or stripped.startswith('"id"'):
        print(number, stripped[:130])
