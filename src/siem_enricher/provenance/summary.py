"""Материализованные сводки цепочек: компонента графа и её агрегаты.

Смысл: вместо обхода графа на каждое событие поддерживаем объединение компонент
(union-find) и храним в корне компоненты агрегаты — рёбра, число шагов, внешние
адресаты. При добавлении ребра компоненты сливаются, агрегаты объединяются,
поэтому `chain_for` не выполняет поиск в ширину.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from siem_enricher.provenance.graph import ProvenanceEdge, ProvenanceNode

MAX_EDGES_PER_COMPONENT = 96


@dataclass
class Component:
    """Агрегированное состояние одной связной компоненты графа."""

    edges: dict[object, ProvenanceEdge] = field(default_factory=dict)
    external: dict[str, str] = field(default_factory=dict)
    nodes: set[str] = field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def add_edge(self, edge: ProvenanceEdge) -> None:
        key: object = edge.edge_id if edge.edge_id is not None else f"{edge.src}|{edge.dst}|{edge.timestamp}"
        self.edges[key] = edge
        if len(self.edges) > MAX_EDGES_PER_COMPONENT:
            ordered = sorted(self.edges.items(), key=lambda item: item[1].timestamp)
            self.edges = dict(ordered[-MAX_EDGES_PER_COMPONENT:])
        self.nodes.update((edge.src, edge.dst))
        if self.first_seen is None or edge.timestamp < self.first_seen:
            self.first_seen = edge.timestamp
        if self.last_seen is None or edge.timestamp > self.last_seen:
            self.last_seen = edge.timestamp

    def add_node(self, node: ProvenanceNode) -> None:
        self.nodes.add(node.id)
        if self.first_seen is None or node.first_seen < self.first_seen:
            self.first_seen = node.first_seen
        if self.last_seen is None or node.last_seen > self.last_seen:
            self.last_seen = node.last_seen

    def merge(self, other: Component) -> None:
        for key, edge in other.edges.items():
            self.edges.setdefault(key, edge)
        if len(self.edges) > MAX_EDGES_PER_COMPONENT:
            ordered = sorted(self.edges.items(), key=lambda item: item[1].timestamp)
            self.edges = dict(ordered[-MAX_EDGES_PER_COMPONENT:])
        self.external.update(other.external)
        self.nodes.update(other.nodes)
        if other.first_seen and (self.first_seen is None or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and (self.last_seen is None or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen


class ChainSummaries:
    """Union-find по узлам графа плюс агрегаты компонент."""

    def __init__(self, max_components: int = 20000) -> None:
        self._parent: dict[str, str] = {}
        self._components: dict[str, Component] = {}
        self.max_components = max_components

    def _ensure(self, node_id: str) -> str:
        parent = self._parent.get(node_id)
        if parent is None:
            self._parent[node_id] = node_id
            self._components.setdefault(node_id, Component())
            return node_id
        while parent != self._parent.get(parent, parent):
            self._parent[node_id] = self._parent[parent]
            node_id, parent = parent, self._parent[parent]
        return parent

    def find(self, node_id: str) -> str | None:
        if node_id not in self._parent:
            return None
        root = self._ensure(node_id)
        while root != self._parent[root]:
            root = self._parent[root]
        return root

    def union(self, left: str, right: str) -> str:
        left_root, right_root = self._ensure(left), self._ensure(right)
        if left_root == right_root:
            return left_root
        target, source = (left_root, right_root) if left_root < right_root else (right_root, left_root)
        self._components[target].merge(self._components.pop(source, Component()))
        self._parent[source] = target
        return target

    def add_edge(self, edge: ProvenanceEdge) -> str:
        root = self.union(edge.src, edge.dst)
        self._components.setdefault(root, Component()).add_edge(edge)
        return root

    def add_node(self, node: ProvenanceNode) -> str:
        root = self._ensure(node.id)
        self._components.setdefault(root, Component()).add_node(node)
        return root

    def add_external(self, node: ProvenanceNode) -> str:
        """Учесть внешний адресат: он попадёт в сводку компоненты."""
        root = self._ensure(node.id)
        component = self._components.setdefault(root, Component())
        component.external[node.id] = node.label
        component.nodes.add(node.id)
        return root

    def component_for(self, node_id: str) -> Component | None:
        root = self.find(node_id)
        if root is None:
            return None
        return self._components.get(root)

    def edges_for(self, node_id: str) -> list[ProvenanceEdge]:
        component = self.component_for(node_id)
        if component is None:
            return []
        return sorted(component.edges.values(), key=lambda edge: edge.timestamp)

    def externals_for(self, node_id: str) -> list[str]:
        component = self.component_for(node_id)
        if component is None:
            return []
        return list(dict.fromkeys(component.external.values()))

    def clear(self) -> None:
        self._parent.clear()
        self._components.clear()

    def size(self) -> int:
        return len(self._components)


__all__ = ["ChainSummaries", "Component", "MAX_EDGES_PER_COMPONENT"]
