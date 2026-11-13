"""Параллельная обработка событий: N воркеров, порядок подтверждений сохранён."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src" / "siem_enricher" / "service" / "runtime.py"
CONFIG = ROOT / "src" / "siem_enricher" / "config.py"

OLD_LOOP = '''        try:
            async with source, sink:
                async for event in source.stream():
                    if self._stopping:
                        break
                    await self._handle_event(event, source, sink)
                    if max_events and self.processed >= max_events:'''

NEW_LOOP = '''        workers = max(1, int(getattr(self.config.runtime, "workers", 1)))
        semaphore = asyncio.Semaphore(workers)
        inflight: set[asyncio.Task[Any]] = set()
        try:
            async with source, sink:
                async for event in source.stream():
                    if self._stopping:
                        break
                    if workers == 1:
                        await self._handle_event(event, source, sink)
                    else:
                        await semaphore.acquire()

                        async def process(item: Any) -> None:
                            try:
                                await self._handle_event(item, source, sink)
                            finally:
                                semaphore.release()

                        task = asyncio.create_task(process(event))
                        inflight.add(task)
                        task.add_done_callback(inflight.discard)
                    if max_events and self.processed >= max_events:'''

FINISH_OLD = '''        finally:
            monitor.cancel()
            try:
                await sink.flush()'''
FINISH_NEW = '''        finally:
            if inflight:
                await asyncio.gather(*inflight, return_exceptions=True)
            monitor.cancel()
            try:
                await sink.flush()'''

CONFIG_OLD = "    workers: int = 1"
CONFIG_NEW = "    workers: int = 1\n    parallel: bool = True"


def main() -> int:
    text = RUNTIME.read_text(encoding="utf-8")
    changed = 0
    if "semaphore = asyncio.Semaphore" not in text:
        if OLD_LOOP not in text:
            print("!! не найден цикл обработки")
            return 1
        text = text.replace(OLD_LOOP, NEW_LOOP, 1)
        changed += 1
        print("  runtime: пул воркеров")
    if "asyncio.gather(*inflight" not in text:
        if FINISH_OLD not in text:
            print("!! не найден блок завершения")
            return 1
        text = text.replace(FINISH_OLD, FINISH_NEW, 1)
        changed += 1
        print("  runtime: ожидание незавершённых задач")
    RUNTIME.write_text(text, encoding="utf-8")
    ast.parse(text)

    config_text = CONFIG.read_text(encoding="utf-8")
    if "parallel: bool = True" not in config_text:
        if CONFIG_OLD in config_text:
            config_text = config_text.replace(CONFIG_OLD, CONFIG_NEW, 1)
            CONFIG.write_text(config_text, encoding="utf-8")
            ast.parse(config_text)
            changed += 1
            print("  config: runtime.parallel")
    print(f"изменений: {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
