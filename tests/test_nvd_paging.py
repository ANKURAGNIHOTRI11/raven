import asyncio, json
import httpx, pytest
import importlib.util
from pathlib import Path

# Several services have a main.py, so load the crawler's by path under a unique name.
_spec = importlib.util.spec_from_file_location(
    "raven_crawler_main", Path(__file__).resolve().parents[1] / "services" / "crawler" / "main.py")
crawler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crawler)


class FakeClient:
    def __init__(self, total, page_size, fail_first=0):
        self.total, self.size, self.fail, self.calls = total, page_size, fail_first, []

    async def get(self, url, params=None, headers=None, timeout=None):
        if self.fail > 0:
            self.fail -= 1
            raise httpx.ReadTimeout("slow")
        start = params["startIndex"]; self.calls.append(start)
        n = max(0, min(self.size, self.total - start))
        body = {"resultsPerPage": n, "startIndex": start, "totalResults": self.total,
                "vulnerabilities": [{"cve": {"id": f"CVE-2026-{start+i:05d}"}} for i in range(n)]}
        return httpx.Response(200, json=body, request=httpx.Request("GET", url))


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    async def nosleep(*_a, **_k): return None
    monkeypatch.setattr(crawler.asyncio, "sleep", nosleep)


SRC = {"parser": "nvd", "url": "https://nvd.example/cves", "source_id": "nvd"}


def test_all_pages_are_merged():
    c = FakeClient(total=4500, page_size=2000)
    out = json.loads(asyncio.run(crawler.fetch_nvd(c, SRC)))
    assert len(out["vulnerabilities"]) == 4500 and c.calls == [0, 2000, 4000]


def test_timeout_is_retried_then_succeeds():
    c = FakeClient(total=10, page_size=2000, fail_first=2)
    out = json.loads(asyncio.run(crawler.fetch_nvd(c, SRC)))
    assert len(out["vulnerabilities"]) == 10


def test_empty_window_returns_empty_list():
    out = json.loads(asyncio.run(crawler.fetch_nvd(FakeClient(0, 2000), SRC)))
    assert out["vulnerabilities"] == []


class GhsaClient:
    """Serves `pages` pages of 100 advisories, each with a rel=next link until the last."""
    def __init__(self, pages): self.pages, self.n = pages, 0

    async def get(self, url, params=None, headers=None, timeout=None):
        i = self.n; self.n += 1
        hdr = {"Link": '<https://api.github.com/advisories?after=x>; rel="next"'} if i < self.pages - 1 else {}
        return httpx.Response(200, json=[{"ghsa_id": f"GHSA-{i}-{j}"} for j in range(100)],
                              headers=hdr, request=httpx.Request("GET", url))


GHSA = {"parser": "ghsa", "url": "https://api.github.com/advisories", "source_id": "ghsa"}


def test_ghsa_follows_more_than_five_pages():
    items = asyncio.run(crawler.fetch_paginated(GhsaClient(pages=9), GHSA))
    assert len(items) == 900


def test_ghsa_stops_at_cap(monkeypatch):
    c = GhsaClient(pages=crawler.MAX_PAGES + 10)
    items = asyncio.run(crawler.fetch_paginated(c, GHSA))
    assert len(items) == crawler.MAX_PAGES * 100 and c.n == crawler.MAX_PAGES
