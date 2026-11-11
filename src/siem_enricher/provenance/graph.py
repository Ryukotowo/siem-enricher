"""Модель графа происхождения данных."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from siem_enricher.models.enums import EntityKind, ProvenanceAction
from siem_enricher.models.event import isoformat, parse_timestamp, utcnow


def normalize_key(key: str) -> str:
    """Нормализовать ключ сущности (пути нечувствительны к регистру в Windows)."""
    return (key or "").strip().replace("/", "\\").rstrip("\\").lower()


def make_node_id(kind: EntityKind, key: str) -> str:
    """Идентификатор узла графа."""
    return f"{kind.value}:{normalize_key(key)}"


@dataclass(slots=True)
class ProvenanceNode:
    """Узел графа происхождения."""

    id: str
    kind: EntityKind
    key: str
    label: str
    first_seen: datetime = field(default_factory=utcnow)
    last_seen: datetime = field(default_factory=utcnow)
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        kind: EntityKind,
        key: str,
        label: str | None = None,
        timestamp: datetime | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> ProvenanceNode:
        ts = timestamp or utcnow()
        return cls(
            id=make_node_id(kind, key),
            kind=kind,
            key=normalize_key(key),
            label=label or key,
            first_seen=ts,
            last_seen=ts,
            attributes=dict(attributes or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "key": self.key,
            "label": self.label,
            "first_seen": isoformat(self.first_seen),
            "last_seen": isoformat(self.last_seen),
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvenanceNode:
        return cls(
            id=str(data["id"]),
            kind=EntityKind(data.get("kind", EntityKind.FILE.value)),
            key=str(data.get("key", "")),
            label=str(data.get("label", data.get("key", ""))),
            first_seen=parse_timestamp(data.get("first_seen")),
            last_seen=parse_timestamp(data.get("last_seen")),
            attributes=dict(data.get("attributes") or {}),
        )


@dataclass(slots=True)
class ProvenanceEdge:
    """Ребро графа: действие субъекта над объектом."""

    src: str
    dst: str
    action: ProvenanceAction
    timestamp: datetime = field(default_factory=utcnow)
    event_id: str | None = None
    host: str | None = None
    user: str | None = None
    process: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    edge_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src": self.src,
            "dst": self.dst,
            "action": self.action.value,
            "timestamp": isoformat(self.timestamp),
            "event_id": self.event_id,
            "host": self.host,
            "user": self.user,
            "process": self.process,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProvenanceEdge:
        return cls(
            src=str(data["src"]),
            dst=str(data["dst"]),
            action=ProvenanceAction.from_value(data.get("action")),
            timestamp=parse_timestamp(data.get("timestamp")),
            event_id=data.get("event_id"),
            host=data.get("host"),
            user=data.get("user"),
            process=data.get("process"),
            attributes=dict(data.get("attributes") or {}),
            edge_id=data.get("edge_id"),
        )


@dataclass(slots=True)
class ProvenanceGraph:
    """Граф происхождения в памяти (используется для отладки и выгрузки)."""

    nodes: dict[str, ProvenanceNode] = field(default_factory=dict)
    edges: list[ProvenanceEdge] = field(default_factory=list)

    def add_node(self, node: ProvenanceNode) -> ProvenanceNode:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.last_seen = max(existing.last_seen, node.last_seen)
        existing.first_seen = min(existing.first_seen, node.first_seen)
        existing.attributes.update(node.attributes)
        return existing

    def add_edge(self, edge: ProvenanceEdge) -> ProvenanceEdge:
        edge.edge_id = len(self.edges) + 1
        self.edges.append(edge)
        return edge

    def edges_for(self, node_id: str) -> list[ProvenanceEdge]:
        return [e for e in self.edges if e.src == node_id or e.dst == node_id]

    def neighbors(self, node_id: str) -> set[str]:
        result: set[str] = set()
        for edge in self.edges_for(node_id):
            result.add(edge.dst if edge.src == node_id else edge.src)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def stats(self) -> dict[str, int]:
        return {"nodes": len(self.nodes), "edges": len(self.edges)}


def iter_node_ids(items: Iterable[ProvenanceNode]) -> list[str]:
    return [node.id for node in items]
