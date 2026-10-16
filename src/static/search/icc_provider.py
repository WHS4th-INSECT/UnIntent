from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from src.static.model.values import ICCEdge, SinkSite


SiteResolution: TypeAlias = list[ICCEdge] | tuple[list[ICCEdge], bool]


class DemandICCProvider:
    """Materialize outgoing ICC state only when a receiver needs it.

    The lightweight DEX pass supplies constant target hints.  Resolving an
    incoming component asks only the dispatch sites that can name that
    component; unrelated ICC sites never run Intent-state analysis.
    """

    def __init__(
        self,
        sites: list[SinkSite],
        target_hints: dict[str, set[str]],
        resolve_site: Callable[[SinkSite], SiteResolution],
        supplemental_providers: tuple[object, ...] = (),
    ) -> None:
        self.sites_by_id = {site.site_id: site for site in sites}
        self._resolve_site = resolve_site
        self._supplemental_providers = supplemental_providers
        self._site_cache: dict[str, tuple[ICCEdge, ...]] = {}
        self._incoming_site_ids: dict[str, list[str]] = {}
        for site in sites:
            for target in target_hints.get(site.site_id, ()):
                self._incoming_site_ids.setdefault(target, []).append(site.site_id)
        self.requests = 0
        self.site_resolutions = 0
        self.cache_hits = 0
        self.incomplete_site_resolutions = 0
        self.last_request_complete = True
        self._last_site_resolution_complete = True

    def resolve_site(self, site_id: str) -> list[ICCEdge]:
        cached = self._site_cache.get(site_id)
        if cached is not None:
            self.cache_hits += 1
            self._last_site_resolution_complete = True
            return list(cached)
        site = self.sites_by_id.get(site_id)
        if site is None:
            return []
        resolution = self._resolve_site(site)
        if isinstance(resolution, tuple):
            resolved_edges, complete = resolution
        else:
            resolved_edges, complete = resolution, True
        edges = tuple(resolved_edges)
        self._last_site_resolution_complete = complete
        if complete:
            self._site_cache[site_id] = edges
        else:
            self.incomplete_site_resolutions += 1
        self.site_resolutions += 1
        return list(edges)

    def incoming_edges(self, target_component: str) -> list[ICCEdge]:
        self.requests += 1
        self.last_request_complete = True
        result: list[ICCEdge] = []
        for site_id in self._incoming_site_ids.get(target_component, ()):
            site_edges = self.resolve_site(site_id)
            self.last_request_complete = (
                self.last_request_complete and self._last_site_resolution_complete
            )
            result.extend(
                edge for edge in site_edges if edge.target_component == target_component
            )
        for provider in self._supplemental_providers:
            incoming = getattr(provider, "incoming_edges", None)
            if not callable(incoming):
                continue
            result.extend(incoming(target_component))
            provider_sites = getattr(provider, "sites_by_id", None)
            if isinstance(provider_sites, dict):
                self.sites_by_id.update(provider_sites)
        return result

    @property
    def materialized_edges_by_site(self) -> dict[str, list[ICCEdge]]:
        return {key: list(value) for key, value in self._site_cache.items()}

    @property
    def materialized_edges(self) -> list[ICCEdge]:
        result = [edge for edges in self._site_cache.values() for edge in edges]
        for provider in self._supplemental_providers:
            cache = getattr(provider, "_cache", {})
            if isinstance(cache, dict):
                result.extend(edge for edges in cache.values() for edge in edges)
        return result

    def metrics(self) -> dict[str, int]:
        result = {
            "demand_icc_requests": self.requests,
            "demand_icc_site_resolutions": self.site_resolutions,
            "demand_icc_cache_hits": self.cache_hits,
            "demand_icc_incomplete_site_resolutions": self.incomplete_site_resolutions,
            "demand_icc_unmaterialized_sites": len(self.sites_by_id) - len(self._site_cache),
        }
        for provider in self._supplemental_providers:
            provider_metrics = getattr(provider, "metrics", None)
            if callable(provider_metrics):
                result.update(provider_metrics())
        return result
