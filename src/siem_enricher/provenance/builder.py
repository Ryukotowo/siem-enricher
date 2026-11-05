"""Построение цепочек происхождения файлов."""

from __future__ import annotations

from datetime import datetime, timedelta
from collections import OrderedDict
from typing import Iterable, Sequence

from siem_enricher.config import ProvenanceConfig
from siem_enricher.logging_setup import get_logger
from siem_enricher.models.enums import EntityKind, ProvenanceAction
from siem_enricher.models.enrichment import ProvenanceChain, ProvenanceStep
from siem_enricher.models.event import NormalizedEvent, utcnow
from siem_enricher.provenance.graph import (
    ProvenanceEdge,
    ProvenanceGraph,
    ProvenanceNode,
    make_node_id,
)
from siem_enricher.provenance.store import ProvenanceStore

logger = get_logger("provenance.builder")

#: Действия, означающие «файл является источником» (из него копируют/читают)
SOURCE_ACTIONS = {ProvenanceAction.READ}
#: Действия, означающие «файл является результатом»
DESTINATION_ACTIONS = {
    ProvenanceAction.CREATE, ProvenanceAction.WRITE, ProvenanceAction.COPY,
    ProvenanceAction.MOVE, ProvenanceAction.RENAME,
}
EXTERNAL_KINDS = {EntityKind.ENDPOINT, EntityKind.URL}


class ProvenanceBuilder:
    """Строит граф происхождения по событиям и восстанавливает цепочки для файлов."""

    def __init__(
        self,
        store: ProvenanceStore,
        max_chain_depth: int = 16,
        ttl_seconds: int = 604800,
        external_actions: Iterable[str] = ("upload", "send"),
    ) -> None:
        self.store = store
        self.max_chain_depth = max_chain_depth
        self.chain_cache_size = 4096
        self._chain_cache: OrderedDict[tuple[str, object], tuple[int, object]] = OrderedDict()
        self._edge_epoch = 0
        self.edge_limit = 400
        self.ttl_seconds = ttl_seconds
        self.external_actions = {str(a).lower() for a in external_actions}

    @classmethod
    def from_config(cls, config: ProvenanceConfig, store: ProvenanceStore) -> ProvenanceBuilder:
        return cls(
            store=store,
            max_chain_depth=config.max_chain_depth,
            ttl_seconds=config.ttl_seconds,
            external_actions=config.external_actions,
        )

    def record(self, event: NormalizedEvent) -> ProvenanceGraph:
        """Разобрать событие в узлы и рёбра графа и сохранить их в хранилище."""
        graph = self.build(event)
        if graph.nodes:
            self.store.upsert_nodes(list(graph.nodes.values()))
        if graph.edges:
            self.store.add_edges(graph.edges)
            self._edge_epoch += len(graph.edges)
            self._invalidate_touched(event)
        return graph

    def _invalidate_touched(self, event: NormalizedEvent) -> None:
        """Сбросить кэш только для путей, которых коснулось событие."""
        touched = {
            str(item.path).strip().lower()
            for item in (event.files or [])
            if getattr(item, "path", None)
        }
        if not touched or not self._chain_cache:
            return
        for key in [key for key in self._chain_cache if key[0] in touched]:
            self._chain_cache.pop(key, None)

    def build(self, event: NormalizedEvent) -> ProvenanceGraph:
        """Построить граф происхождения для одного события (без сохранения)."""
        graph = ProvenanceGraph()
        timestamp = event.timestamp

        process_node = self._process_node(event, timestamp)
        user_node = self._user_node(event, timestamp)
        if process_node:
            graph.add_node(process_node)
        if user_node:
            graph.add_node(user_node)
        if process_node and user_node:
            graph.add_edge(
                ProvenanceEdge(
                    src=user_node.id,
                    dst=process_node.id,
                    action=ProvenanceAction.EXECUTE,
                    timestamp=timestamp,
                    event_id=event.event_id,
                    host=event.host,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                    attributes={"relation": "запуск процесса пользователем"},
                )
            )
        actor = process_node or user_node

        file_nodes: dict[str, ProvenanceNode] = {}
        for file_ref in event.files:
            node = ProvenanceNode.create(
                EntityKind.FILE,
                file_ref.path,
                label=file_ref.path,
                timestamp=timestamp,
                attributes={
                    "extension": file_ref.extension,
                    "size_bytes": file_ref.size_bytes,
                    "sha256": file_ref.sha256,
                    "hosts": [event.host] if event.host else [],
                    "sources": [file_ref.source_field] if file_ref.source_field else [],
                },
            )
            graph.add_node(node)
            file_nodes[file_ref.key] = node
            if actor is not None:
                graph.add_edge(
                    ProvenanceEdge(
                        src=actor.id,
                        dst=node.id,
                        action=file_ref.action or event.action,
                        timestamp=timestamp,
                        event_id=event.event_id,
                        host=event.host,
                        user=event.user.name if event.user else None,
                        process=event.process.name if event.process else None,
                        attributes={"source_field": file_ref.source_field, "embedded": file_ref.is_embedded},
                    )
                )

        endpoint_node = self._endpoint_node(event, timestamp)
        if endpoint_node is not None:
            graph.add_node(endpoint_node)
            targets = list(file_nodes.values()) or [actor]
            for target in targets:
                if target is None:
                    continue
                graph.add_edge(
                    ProvenanceEdge(
                        src=target.id,
                        dst=endpoint_node.id,
                        action=event.action if event.action.is_external_flow else ProvenanceAction.SEND,
                        timestamp=timestamp,
                        event_id=event.event_id,
                        host=event.host,
                        user=event.user.name if event.user else None,
                        process=event.process.name if event.process else None,
                        attributes={"relation": "передача данных во внешний адрес"},
                    )
                )

        # Цепочка «источник -> результат» внутри одного события (копирование/перемещение)
        sources = [f for f in event.files if f.action in SOURCE_ACTIONS]
        destinations = [f for f in event.files if f.action in DESTINATION_ACTIONS]
        for source in sources:
            source_node = file_nodes.get(source.key)
            if source_node is None:
                continue
            for destination in destinations:
                destination_node = file_nodes.get(destination.key)
                if destination_node is None or destination_node.id == source_node.id:
                    continue
                relation = (
                    event.action if event.action in {ProvenanceAction.COPY, ProvenanceAction.MOVE,
                                                     ProvenanceAction.RENAME}
                    else ProvenanceAction.COPY
                )
                graph.add_edge(
                    ProvenanceEdge(
                        src=source_node.id,
                        dst=destination_node.id,
                        action=relation,
                        timestamp=timestamp,
                        event_id=event.event_id,
                        host=event.host,
                        user=event.user.name if event.user else None,
                        process=event.process.name if event.process else None,
                        attributes={"relation": "копирование внутри события"},
                    )
                )
        return graph

    def chain_for(
        self,
        file_path: str,
        event: NormalizedEvent | None = None,
        as_of: datetime | None = None,
    ) -> ProvenanceChain:
        """Восстановить цепочку происхождения файла по накопленному графу."""
        cache_key = (str(file_path).strip().lower(), as_of)
        cached = self._chain_cache.get(cache_key)
        if cached is not None and event is None:
            epoch, chain = cached
            if epoch == self._edge_epoch:
                self._chain_cache.move_to_end(cache_key)
                return chain  # type: ignore[return-value]
            self._chain_cache.pop(cache_key, None)

        file_node_id = make_node_id(EntityKind.FILE, file_path)
        collected: dict[int | str, ProvenanceEdge] = {}
        visited: set[str] = {file_node_id}
        frontier: set[str] = {file_node_id}

        for _ in range(self.max_chain_depth):
            if not frontier:
                break
            edges = self.store.edges_touching(sorted(frontier), limit=self.edge_limit)
            next_frontier: set[str] = set()
            for edge in edges:
                key: int | str = edge.edge_id if edge.edge_id is not None else f"{edge.src}|{edge.dst}|{edge.timestamp}"
                if key in collected:
                    continue
                collected[key] = edge
                for node_id in (edge.src, edge.dst):
                    if node_id not in visited:
                        visited.add(node_id)
                        next_frontier.add(node_id)
            frontier = next_frontier

        reference = event.timestamp if event is not None else (as_of or utcnow())
        cutoff = reference - timedelta(seconds=self.ttl_seconds)
        edges = [e for e in collected.values() if e.timestamp >= cutoff]
        edges.sort(key=lambda e: e.timestamp)
        nodes = self.store.get_nodes(sorted(visited))

        steps = [self._step(edge, file_node_id, nodes, file_path) for edge in edges]
        steps = _dedupe_steps(steps)

        if not steps and event is not None:
            steps = [self._synthetic_step(event, file_path)]

        endpoints: list[str] = []
        for node in nodes.values():
            if node.kind in EXTERNAL_KINDS and node.id in visited:
                candidates = [node.label]
                if node.kind == EntityKind.ENDPOINT:
                    candidates = [node.label]
                for candidate in candidates:
                    if candidate and candidate not in endpoints and _is_external_node(node):
                        endpoints.append(candidate)

        return ProvenanceChain(file_path=file_path, steps=steps, external_endpoints=endpoints)

    def chains_for(self, event: NormalizedEvent) -> list[ProvenanceChain]:
        """Восстановить цепочки для всех файлов события."""
        return [self.chain_for(file_ref.path, event) for file_ref in event.files]

    def prune(self) -> int:
        """Удалить устаревшие записи графа."""
        return self.store.prune(self.ttl_seconds)

    @staticmethod
    def _process_node(event: NormalizedEvent, timestamp: datetime) -> ProvenanceNode | None:
        if not event.process or not event.process.name:
            return None
        return ProvenanceNode.create(
            EntityKind.PROCESS,
            event.process.key,
            label=event.process.name,
            timestamp=timestamp,
            attributes={
                "path": event.process.path,
                "pid": event.process.pid,
                "cmdline": event.process.cmdline,
                "parent_name": event.process.parent_name,
                "parent_path": event.process.parent_path,
                "integrity_level": event.process.integrity_level,
            },
        )

    @staticmethod
    def _user_node(event: NormalizedEvent, timestamp: datetime) -> ProvenanceNode | None:
        if not event.user or not event.user.name:
            return None
        return ProvenanceNode.create(
            EntityKind.USER,
            event.user.key,
            label=event.user.name,
            timestamp=timestamp,
            attributes={
                "domain": event.user.domain,
                "is_privileged": event.user.is_privileged,
            },
        )

    @staticmethod
    def _endpoint_node(event: NormalizedEvent, timestamp: datetime) -> ProvenanceNode | None:
        remote = event.remote
        if remote is None or not remote.key or remote.key == "unknown":
            return None
        kind = EntityKind.URL if (remote.url or remote.domain) else EntityKind.ENDPOINT
        return ProvenanceNode.create(
            kind,
            remote.key,
            label=remote.url or remote.domain or remote.ip or "unknown",
            timestamp=timestamp,
            attributes={
                "ip": remote.ip,
                "port": remote.port,
                "domain": remote.domain,
                "url": remote.url,
                "direction": remote.direction,
                "is_external": remote.is_external,
            },
        )

    @staticmethod
    def _step(
        edge: ProvenanceEdge,
        file_node_id: str,
        nodes: dict[str, ProvenanceNode],
        original_path: str,
    ) -> ProvenanceStep:
        source = nodes.get(edge.src)
        target = nodes.get(edge.dst)
        direction = "self"
        endpoint: str | None = None
        counterpart: str | None = None

        if edge.src == file_node_id:
            other = target
            if other is not None and other.kind in EXTERNAL_KINDS:
                direction, endpoint = "outbound", other.label
            elif other is not None and other.kind == EntityKind.FILE:
                direction, counterpart = "outbound", other.label
        elif edge.dst == file_node_id:
            other = source
            if other is not None and other.kind == EntityKind.FILE:
                direction, counterpart = "inbound", other.label
            elif other is not None and other.kind in EXTERNAL_KINDS:
                direction, endpoint = "inbound", other.label

        note = ""
        if direction == "self" and source is not None:
            note = f"действие {edge.action.value}: субъект {source.kind.value} {source.label}"

        file_node = nodes.get(file_node_id)
        path = original_path or (file_node.label if file_node else "")
        return ProvenanceStep(
            timestamp=edge.timestamp,
            action=edge.action,
            path=path,
            actor_user=edge.user,
            actor_process=edge.process,
            host=edge.host,
            event_id=edge.event_id,
            endpoint=endpoint,
            direction=direction,
            counterpart_path=counterpart,
            note=note,
        )

    @staticmethod
    def _synthetic_step(event: NormalizedEvent, file_path: str) -> ProvenanceStep:
        """Шаг для файла, который встретился впервые (граф ещё пуст)."""
        return ProvenanceStep(
            timestamp=event.timestamp,
            action=event.action,
            path=file_path,
            actor_user=event.user.name if event.user else None,
            actor_process=event.process.name if event.process else None,
            host=event.host,
            event_id=event.event_id,
            direction="self",
            note="первое наблюдение объекта в обработанном потоке событий",
        )


def _is_external_node(node: ProvenanceNode) -> bool:
    """Является ли узел внешним получателем данных."""
    value = node.attributes.get("is_external")
    if value is None:
        # Для URL/доменов считаем адрес внешним по умолчанию
        return node.kind == EntityKind.URL
    return bool(value)


def _dedupe_steps(steps: Sequence[ProvenanceStep]) -> list[ProvenanceStep]:
    """Убрать дубли шагов (одно и то же действие в одном событии)."""
    seen: set[tuple[str, str, str, str]] = set()
    result: list[ProvenanceStep] = []
    for step in steps:
        key = (step.event_id or "", step.action.value, step.path, step.counterpart_path or step.endpoint or "")
        if key in seen:
            continue
        seen.add(key)
        result.append(step)
    return result
