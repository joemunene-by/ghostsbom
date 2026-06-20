"""OSV.dev client and a protocol so the scanner can be tested offline.

The real client talks to the OSV.dev batch API. The scanner depends on the
``OSVClient`` protocol, so tests inject a fake client returning canned data and
never touch the network.
"""

from __future__ import annotations

import logging
import time
from typing import Protocol

import httpx

from .models import OSV_ECOSYSTEM, Component

logger = logging.getLogger("ghostsbom.osv")

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"


class OSVClient(Protocol):
    """Interface the scanner depends on."""

    def query_batch(self, components: list[Component]) -> dict[str, list[str]]:
        """Map each component key to a list of vulnerability ids."""
        ...

    def get_vuln(self, vuln_id: str) -> dict:
        """Return the full OSV record for a vulnerability id."""
        ...


class OfflineOSVClient:
    """A client that reports no vulnerabilities. Used by ``--offline`` mode."""

    def query_batch(self, components: list[Component]) -> dict[str, list[str]]:
        return {c.key(): [] for c in components}

    def get_vuln(self, vuln_id: str) -> dict:
        return {}


class HTTPOSVClient:
    """Real OSV.dev client built on httpx, with timeouts and retries."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 0.5,
    ) -> None:
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._retries = max(1, retries)
        self._backoff = backoff
        self._vuln_cache: dict[str, dict] = {}

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HTTPOSVClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _post(self, url: str, json_body: dict) -> dict:
        last_exc: Exception | None = None
        for attempt in range(1, self._retries + 1):
            try:
                response = self._client.post(url, json=json_body)
                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        "server error", request=response.request, response=response
                    )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_exc = exc
                logger.warning("OSV POST %s failed (attempt %d): %s", url, attempt, exc)
                if attempt < self._retries:
                    time.sleep(self._backoff * attempt)
        raise RuntimeError(f"OSV request failed after {self._retries} attempts: {last_exc}")

    def _get(self, url: str) -> dict:
        last_exc: Exception | None = None
        for attempt in range(1, self._retries + 1):
            try:
                response = self._client.get(url)
                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        "server error", request=response.request, response=response
                    )
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_exc = exc
                logger.warning("OSV GET %s failed (attempt %d): %s", url, attempt, exc)
                if attempt < self._retries:
                    time.sleep(self._backoff * attempt)
        raise RuntimeError(f"OSV request failed after {self._retries} attempts: {last_exc}")

    def query_batch(self, components: list[Component]) -> dict[str, list[str]]:
        if not components:
            return {}
        queries = [
            {
                "version": c.version,
                "package": {
                    "name": c.name,
                    "ecosystem": OSV_ECOSYSTEM.get(c.ecosystem, c.ecosystem),
                },
            }
            for c in components
        ]
        payload = self._post(OSV_QUERYBATCH_URL, {"queries": queries})
        results = payload.get("results", [])
        mapping: dict[str, list[str]] = {}
        for component, result in zip(components, results, strict=False):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            mapping[component.key()] = [v["id"] for v in vulns if "id" in v]
        return mapping

    def get_vuln(self, vuln_id: str) -> dict:
        if vuln_id in self._vuln_cache:
            return self._vuln_cache[vuln_id]
        record = self._get(OSV_VULN_URL.format(vuln_id=vuln_id))
        self._vuln_cache[vuln_id] = record
        return record
