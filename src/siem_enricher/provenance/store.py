"""Хранилища графа происхождения."""

from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Sequence

from siem_enricher.config import ProvenanceConfig
from siem_enricher.logging_setup import get_logger
from siem_enricher.models.enums import EntityKind, ProvenanceAction
from siem_enricher.models.event import isoformat, parse_timestamp, utcnow
from siem_enricher.provenance.graph import ProvenanceEdge, ProvenanceGraph, ProvenanceNode

logger = get_logger("provenance.store")

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    key         TEXT NOT NULL,
    label       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    attributes  TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    action      TEXT NOT NULL,
    event_id    TEXT,
    host        TEXT,
    user        TEXT,
    process     TEXT,
    attributes  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src, ts);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst, ts);
CREATE INDEX IF NOT EXISTS idx_edges_ts ON edges(ts);
CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
"""


class ProvenanceStore(ABC):
    """Абстрактное хранилище графа происхождения."""

    backend = "abstract"

    def _commit_if_needed(self) -> None:
        """Фиксировать транзакцию не на каждое событие, а пачками."""
        connection = getattr(self, "_conn", None)
        if connection is None:
            return
        self._pending = getattr(self, "_pending", 0) + 1
        if self._pending >= getattr(self, "commit_every", 200):
            connection.commit()
            self._pending = 0

    def flush(self) -> None:
        """Принудительно записать накопленные изменения на диск."""
        connection = getattr(self, "_conn", None)
        lock = getattr(self, "_lock", None)
        if connection is None or lock is None:
            return
        with lock:
            connection.commit()
            self._pending = 0

    @abstractmethod
    def upsert_nodes(self, nodes: Sequence[ProvenanceNode]) -> int:
        """Добавить или обновить узлы."""

    @abstractmethod
    def add_edges(self, edges: Sequence[ProvenanceEdge]) -> int:
        """Добавить рёбра."""

    @abstractmethod
    def edges_touching(self, node_ids: Sequence[str], limit: int = 2000) -> list[ProvenanceEdge]:
        """Рёбра, инцидентные хотя бы одному из узлов."""

    @abstractmethod
    def get_nodes(self, node_ids: Sequence[str]) -> dict[str, ProvenanceNode]:
        """Получить узлы по идентификаторам."""

    def prune(self, ttl_seconds: int, now: datetime | None = None) -> int:
        """Удалить устаревшие записи. Возвращает число удалённых рёбер."""
        return 0

    @abstractmethod
    def stats(self) -> dict[str, Any]:
        """Статистика хранилища."""

    def close(self) -> None:
        self.flush()
        """Освободить ресурсы."""

    def store_graph(self, graph: ProvenanceGraph) -> int:
        self.upsert_nodes(list(graph.nodes.values()))
        return self.add_edges(graph.edges)

    def ping(self) -> bool:
        """Проверка доступности хранилища (для ``/readyz``)."""
        try:
            self.stats()
        except Exception:  # noqa: BLE001
            return False
        return True


class InMemoryProvenanceStore(ProvenanceStore):
    """Хранилище в оперативной памяти."""

    backend = "memory"

    def __init__(self, max_edges: int = 200_000) -> None:
        self.max_edges = max_edges
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._lock = threading.Lock()
        self._next_id = 1

    def upsert_nodes(self, nodes: Sequence[ProvenanceNode]) -> int:
        with self._lock:
            for node in nodes:
                existing = self._nodes.get(node.id)
                if existing is None:
                    self._nodes[node.id] = node
                else:
                    existing.first_seen = min(existing.first_seen, node.first_seen)
                    existing.last_seen = max(existing.last_seen, node.last_seen)
                    existing.attributes.update(node.attributes)
            return len(nodes)

    def add_edges(self, edges: Sequence[ProvenanceEdge]) -> int:
        with self._lock:
            for edge in edges:
                edge.edge_id = self._next_id
                self._next_id += 1
                self._edges.append(edge)
            if len(self._edges) > self.max_edges:
                self._edges = self._edges[-self.max_edges:]
            return len(edges)

    def edges_touching(self, node_ids: Sequence[str], limit: int = 2000) -> list[ProvenanceEdge]:
        wanted = set(node_ids)
        with self._lock:
            result = [e for e in self._edges if e.src in wanted or e.dst in wanted]
        return result[:limit]

    def get_nodes(self, node_ids: Sequence[str]) -> dict[str, ProvenanceNode]:
        with self._lock:
            return {nid: self._nodes[nid] for nid in node_ids if nid in self._nodes}

    def prune(self, ttl_seconds: int, now: datetime | None = None) -> int:
        threshold = (now or utcnow()) - timedelta(seconds=ttl_seconds)
        with self._lock:
            before = len(self._edges)
            self._edges = [e for e in self._edges if e.timestamp >= threshold]
            removed = before - len(self._edges)
        return removed

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {"backend": self.backend, "nodes": len(self._nodes), "edges": len(self._edges)}

    def to_graph(self) -> ProvenanceGraph:
        with self._lock:
            return ProvenanceGraph(nodes=dict(self._nodes), edges=list(self._edges))


SQLITE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_ts ON edges(ts);
CREATE INDEX IF NOT EXISTS idx_nodes_kind_key ON nodes(kind, key);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
"""

class SqliteProvenanceStore(ProvenanceStore):
    """Хранилище на SQLite: переживает перезапуск сервиса, не требует внешнего сервера."""

    backend = "sqlite"

    def __init__(self, path: str | Path, wal: bool = True) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            if wal:
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SQLITE_SCHEMA)
            self._conn.executescript(SQLITE_INDEXES)
            self._conn.commit()
        self.commit_every = 200
        self._pending = 0

    def upsert_nodes(self, nodes: Sequence[ProvenanceNode]) -> int:
        if not nodes:
            return 0
        rows = [
            (n.id, n.kind.value, n.key, n.label, isoformat(n.first_seen), isoformat(n.last_seen),
             json.dumps(n.attributes, ensure_ascii=False, default=str))
            for n in nodes
        ]
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO nodes (id, kind, key, label, first_seen, last_seen, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen = MAX(nodes.last_seen, excluded.last_seen),
                    first_seen = MIN(nodes.first_seen, excluded.first_seen),
                    label = excluded.label
                """,
                rows,
            )
            self._commit_if_needed()
        return len(rows)

    def add_edges(self, edges: Sequence[ProvenanceEdge]) -> int:
        if not edges:
            return 0
        rows = [
            (isoformat(e.timestamp), e.src, e.dst, e.action.value, e.event_id, e.host, e.user,
             e.process, json.dumps(e.attributes, ensure_ascii=False, default=str))
            for e in edges
        ]
        with self._lock:
            cursor = self._conn.executemany(
                """
                INSERT INTO edges (ts, src, dst, action, event_id, host, user, process, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._commit_if_needed()
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else len(rows)

    def edges_touching(self, node_ids: Sequence[str], limit: int = 2000) -> list[ProvenanceEdge]:
        if not node_ids:
            return []
        unique = list(dict.fromkeys(node_ids))
        placeholders = ",".join("?" for _ in unique)
        query = (
            f"SELECT id, ts, src, dst, action, event_id, host, user, process, attributes "
            f"FROM edges WHERE src IN ({placeholders}) OR dst IN ({placeholders}) "
            f"ORDER BY ts ASC LIMIT ?"
        )
        params: list[Any] = [*unique, *unique, limit]
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_edge(row) for row in rows]

    def get_nodes(self, node_ids: Sequence[str]) -> dict[str, ProvenanceNode]:
        if not node_ids:
            return {}
        unique = list(dict.fromkeys(node_ids))
        placeholders = ",".join("?" for _ in unique)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT id, kind, key, label, first_seen, last_seen, attributes "
                f"FROM nodes WHERE id IN ({placeholders})",
                unique,
            ).fetchall()
        result: dict[str, ProvenanceNode] = {}
        for row in rows:
            node = self._row_to_node(row)
            result[node.id] = node
        return result

    def prune(self, ttl_seconds: int, now: datetime | None = None) -> int:
        threshold = isoformat((now or utcnow()) - timedelta(seconds=ttl_seconds))
        with self._lock:
            cursor = self._conn.execute("DELETE FROM edges WHERE ts < ?", (threshold,))
            removed = cursor.rowcount or 0
            self._conn.execute(
                """
                DELETE FROM nodes WHERE id NOT IN (SELECT src FROM edges UNION SELECT dst FROM edges)
                """
            )
            self._conn.commit()
        return removed

    def stats(self) -> dict[str, Any]:
        with self._lock:
            nodes = self._conn.execute("SELECT COUNT(*) AS c FROM nodes").fetchone()["c"]
            edges = self._conn.execute("SELECT COUNT(*) AS c FROM edges").fetchone()["c"]
        return {"backend": self.backend, "nodes": int(nodes), "edges": int(edges), "path": str(self.path)}

    def close(self) -> None:
        with self._lock:
            self._conn.commit()
            self._conn.close()

    @staticmethod
    def _row_to_edge(row: sqlite3.Row) -> ProvenanceEdge:
        return ProvenanceEdge(
            edge_id=int(row["id"]),
            timestamp=parse_timestamp(row["ts"]),
            src=row["src"],
            dst=row["dst"],
            action=ProvenanceAction.from_value(row["action"]),
            event_id=row["event_id"],
            host=row["host"],
            user=row["user"],
            process=row["process"],
            attributes=json.loads(row["attributes"] or "{}"),
        )

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> ProvenanceNode:
        return ProvenanceNode(
            id=row["id"],
            kind=EntityKind(row["kind"]),
            key=row["key"],
            label=row["label"],
            first_seen=parse_timestamp(row["first_seen"]),
            last_seen=parse_timestamp(row["last_seen"]),
            attributes=json.loads(row["attributes"] or "{}"),
        )


def build_store(config: ProvenanceConfig, in_memory_for_tests: bool = False) -> ProvenanceStore:
    """Создать хранилище происхождения согласно конфигурации."""
    backend = (config.backend or "sqlite").lower()
    if in_memory_for_tests or backend == "memory":
        return InMemoryProvenanceStore()
    if backend == "sqlite":
        return SqliteProvenanceStore(config.sqlite_path)
    if backend == "redis":
        raise NotImplementedError(
            "Бэкенд Redis для хранилища происхождения запланирован как расширение "
            "(см. docs/06-provenance.md). Используйте backend=sqlite или memory."
        )
    raise ValueError(f"Неизвестный бэкенд хранилища происхождения: {backend!r}")


def iter_edges(store: ProvenanceStore, node_ids: Iterable[str]) -> list[ProvenanceEdge]:
    """Утилита: получить рёбра по набору узлов."""
    return store.edges_touching(list(node_ids))
