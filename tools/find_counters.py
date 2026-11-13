import pathlib

lines = pathlib.Path(
    r"C:\Users\idv1102\Documents\deepseek-harness\default-workspace\siem-enricher\src\siem_enricher\service\panel.py"
).read_text(encoding="utf-8").splitlines()

for number, line in enumerate(lines, 1):
    if any(token in line for token in ("c-total", "c-crit", "c-block", "c-fp")):
        print(number, line.strip()[:150])
