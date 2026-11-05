"""Ускорение SQLite-хранилища: индексы и пакетная фиксация."""

from __future__ import annotations

import ast
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "src" / "siem_enricher" / "provenance" / "store.py"

INDEXES = '''SQLITE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_ts ON edges(ts);
CREATE INDEX IF NOT EXISTS idx_nodes_kind_key ON nodes(kind, key);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
"""

'''

METHODS = '''    def _commit_if_needed(self) -> None:
        """Фиксировать транзакцию не на каждое событие, а пачками."""
        self._pending += 1
        if self._pending >= self.commit_every:
            self._conn.commit()
            self._pending = 0

    def flush(self) -> None:
        """Принудительно записать накопленные изменения на диск."""
        with self._lock:
            self._conn.commit()
            self._pending = 0

    def upsert_nodes('''

INIT_OLD = '''            self._conn.executescript(SQLITE_SCHEMA)
            self._conn.commit()'''
INIT_NEW = '''            self._conn.executescript(SQLITE_SCHEMA)
            self._conn.executescript(SQLITE_INDEXES)
            self._conn.commit()
        self.commit_every = 200
        self._pending = 0'''

COMMIT_NODES_OLD = '''                rows,
            )
            self._conn.commit()
        return len(rows)'''
COMMIT_NODES_NEW = '''                rows,
            )
            self._commit_if_needed()
        return len(rows)'''

COMMIT_EDGES_OLD = '''                rows,
            )
            self._conn.commit()
        return cursor.rowcount'''
COMMIT_EDGES_NEW = '''                rows,
            )
            self._commit_if_needed()
        return cursor.rowcount'''


def main() -> int:
    text = FILE.read_text(encoding="utf-8")
    changed = 0

    if "SQLITE_INDEXES" not in text:
        marker = "class SqliteProvenanceStore("
        text = text.replace(marker, INDEXES + marker, 1)
        changed += 1
        print("добавлены индексы")

    if "def _commit_if_needed" not in text:
        text = text.replace("    def upsert_nodes(", METHODS, 1)
        changed += 1
        print("добавлена пакетная фиксация")

    for old, new, label in (
        (INIT_OLD, INIT_NEW, "инициализация"),
        (COMMIT_NODES_OLD, COMMIT_NODES_NEW, "commit узлов"),
        (COMMIT_EDGES_OLD, COMMIT_EDGES_NEW, "commit рёбер"),
    ):
        if old in text:
            text = text.replace(old, new, 1)
            changed += 1
            print(f"патч: {label}")
        else:
            print(f"!! не найдено: {label}")

    if "self.flush()" not in text and "def close(self)" in text:
        text = text.replace("    def close(self) -> None:", "    def close(self) -> None:\n        self.flush()", 1)
        changed += 1
        print("close() фиксирует остаток")

    FILE.write_text(text, encoding="utf-8")
    ast.parse(text)
    print(f"изменений: {changed}, синтаксис ок")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
