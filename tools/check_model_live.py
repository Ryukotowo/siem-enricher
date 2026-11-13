"""Проверка модели на корректной форме события (файл во вложенном объекте)."""

import json
import urllib.request

EVENTS = [
    {"files": [{"path": r"C:\Бухгалтерия\Договор_поставки_ООО_Ромашка.docx"}]},
    {"filename": r"C:\Общие\пресс-релиз.docx"},
    {"file": {"path": r"C:\Кадры\приказ_об_увольнении.pdf"}},
    {"filepath": r"C:\Секреты\пароли.txt"},
]

for extra in EVENTS:
    payload = {
        "event_id": "check",
        "ts": "2026-11-13T10:00:00Z",
        "action": "read",
        "user": "ivanov",
        "host": "ws-1",
        **extra,
    }
    request = urllib.request.Request(
        "http://127.0.0.1:8081/v1/enrich",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    result = json.loads(urllib.request.urlopen(request, timeout=30).read().decode())
    path = (result.get("files") or [{}])[0].get("path") or "-"
    print(
        f"{result['data_sensitivity']:<13} метод={result['sensitivity_method']:<9} "
        f"модель={result['sensitivity_model_version']:<34} {path[:58]}"
    )
