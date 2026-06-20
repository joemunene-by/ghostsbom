"""HTTPOSVClient tests with mocked HTTP transport (no real network)."""

from __future__ import annotations

import httpx
import pytest

from ghostsbom.models import ECOSYSTEM_PYPI, Component
from ghostsbom.osv import OSV_QUERYBATCH_URL, OSV_VULN_URL, HTTPOSVClient


def test_query_batch_mapping(httpx_mock):
    httpx_mock.add_response(
        url=OSV_QUERYBATCH_URL,
        method="POST",
        json={"results": [{"vulns": [{"id": "GHSA-aaa"}]}, {}]},
    )
    components = [
        Component("urllib3", "1.24.1", ECOSYSTEM_PYPI),
        Component("requests", "2.31.0", ECOSYSTEM_PYPI),
    ]
    with HTTPOSVClient() as client:
        mapping = client.query_batch(components)
    assert mapping[components[0].key()] == ["GHSA-aaa"]
    assert mapping[components[1].key()] == []


def test_get_vuln_caches(httpx_mock):
    url = OSV_VULN_URL.format(vuln_id="GHSA-aaa")
    httpx_mock.add_response(url=url, method="GET", json={"id": "GHSA-aaa", "summary": "x"})
    with HTTPOSVClient() as client:
        first = client.get_vuln("GHSA-aaa")
        second = client.get_vuln("GHSA-aaa")
    assert first == second
    # Only one HTTP request was issued thanks to caching.
    assert len(httpx_mock.get_requests()) == 1


def test_retry_then_succeed(httpx_mock):
    httpx_mock.add_response(url=OSV_QUERYBATCH_URL, method="POST", status_code=503)
    httpx_mock.add_response(
        url=OSV_QUERYBATCH_URL, method="POST", json={"results": [{}]}
    )
    components = [Component("requests", "2.31.0", ECOSYSTEM_PYPI)]
    with HTTPOSVClient(retries=2, backoff=0.0) as client:
        mapping = client.query_batch(components)
    assert mapping[components[0].key()] == []


def test_retry_exhausted_raises(httpx_mock):
    httpx_mock.add_response(url=OSV_QUERYBATCH_URL, method="POST", status_code=500)
    httpx_mock.add_response(url=OSV_QUERYBATCH_URL, method="POST", status_code=500)
    components = [Component("requests", "2.31.0", ECOSYSTEM_PYPI)]
    with HTTPOSVClient(retries=2, backoff=0.0) as client:
        with pytest.raises(RuntimeError):
            client.query_batch(components)


def test_query_batch_empty_no_request(httpx_mock):
    with HTTPOSVClient() as client:
        assert client.query_batch([]) == {}
    assert httpx_mock.get_requests() == []


def test_injected_client(httpx_mock):
    httpx_mock.add_response(
        url=OSV_QUERYBATCH_URL, method="POST", json={"results": [{}]}
    )
    injected = httpx.Client()
    client = HTTPOSVClient(client=injected)
    client.query_batch([Component("requests", "2.31.0", ECOSYSTEM_PYPI)])
    # The injected client is owned by the caller, not closed by HTTPOSVClient.
    client.close()
    assert not injected.is_closed
    injected.close()
