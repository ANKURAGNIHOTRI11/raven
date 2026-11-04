import asyncio, json
from datetime import datetime, timedelta, timezone
import httpx, pytest
import importlib.util
from pathlib import Path
import types

import raven_common.runtime as _runtime


class _TestLog:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


# Several services have a main.py, so load the crawler's by path under a unique name.
# Stub bootstrap only during import to prevent starting a real Prometheus server.
_original_bootstrap = _runtime.bootstrap
try:
    _runtime.bootstrap = lambda service: (
        types.SimpleNamespace(
            feed_lookback_days=30,
            nvd_api_key=None,
            github_token=None,
            otx_api_key=None,
        ),
        _TestLog(),
    )

    _spec = importlib.util.spec_from_file_location(
        "raven_crawler_main",
        Path(__file__).resolve().parents[1] / "services" / "crawler" / "main.py",
    )
    crawler = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(crawler)
finally:
    _runtime.bootstrap = _original_bootstrap


class FakeClient:
    def __init__(self, total, page_size, fail_first=0):
        self.total, self.size, self.fail, self.calls = total, page_size, fail_first, []
        self.windows = []

    async def get(self, url, params=None, headers=None, timeout=None):
        if self.fail > 0:
            self.fail -= 1
            raise httpx.ReadTimeout("slow")
        start = params["startIndex"]; self.calls.append(start)
        self.windows.append((
            params["lastModStartDate"], params["lastModEndDate"]
        ))
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


def test_ghsa_fails_closed_at_cap():
    c = GhsaClient(pages=crawler.MAX_PAGES + 10)
    with pytest.raises(crawler.IncompleteFetchError):
        asyncio.run(crawler.fetch_paginated(c, GHSA))
    assert c.n == crawler.MAX_PAGES


def _parse_nvd_date(value):
    return datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%S.000"
    ).replace(tzinfo=timezone.utc)


def test_nvd_window_uses_last_success_with_five_minute_overlap():
    last_success = datetime(
        2026, 10, 29, 9, 55, 14, tzinfo=timezone.utc
    )
    src = {**SRC, "last_success": last_success}

    _, params, _ = crawler.build_request(src)

    assert params["lastModStartDate"] == "2026-10-29T09:50:14.000"
    assert params["resultsPerPage"] == 2000


def test_nvd_window_uses_lookback_without_last_success():
    days = crawler.settings.feed_lookback_days
    before = datetime.now(timezone.utc)

    _, params, _ = crawler.build_request(SRC)

    after = datetime.now(timezone.utc)
    actual = _parse_nvd_date(params["lastModStartDate"])
    earliest = before - timedelta(days=days, seconds=1)
    latest = after - timedelta(days=days) + timedelta(seconds=1)

    assert earliest <= actual <= latest


def test_nvd_future_last_success_is_clamped():
    before = datetime.now(timezone.utc)
    src = {
        **SRC,
        "last_success": before + timedelta(days=1),
    }

    _, params, _ = crawler.build_request(src)

    after = datetime.now(timezone.utc)
    actual = _parse_nvd_date(params["lastModStartDate"])
    earliest = before - timedelta(minutes=5, seconds=1)
    latest = after - timedelta(minutes=5) + timedelta(seconds=1)

    assert earliest <= actual <= latest



def test_nvd_page_cap_raises_instead_of_returning_partial_results(monkeypatch):
    monkeypatch.setattr(crawler, "NVD_MAX_PAGES", 2)
    client = FakeClient(total=5000, page_size=2000)

    with pytest.raises(crawler.IncompleteFetchError, match="NVD exceeded"):
        asyncio.run(crawler.fetch_nvd(client, SRC))

    assert client.calls == [0, 2000]


def test_nvd_zero_progress_with_remaining_results_is_failure():
    class ZeroProgressClient:
        async def get(self, url, params=None, headers=None, timeout=None):
            body = {
                "resultsPerPage": 0,
                "startIndex": params["startIndex"],
                "totalResults": 10,
                "vulnerabilities": [],
            }
            return httpx.Response(200, json=body, request=httpx.Request("GET", url))

    with pytest.raises(crawler.IncompleteFetchError, match="no pagination progress"):
        asyncio.run(crawler.fetch_nvd(ZeroProgressClient(), SRC))


def test_ghsa_page_cap_raises_instead_of_returning_partial_results(monkeypatch):
    monkeypatch.setattr(crawler, "MAX_PAGES", 2)
    client = GhsaClient(pages=5)

    with pytest.raises(crawler.IncompleteFetchError, match="MAX_PAGES"):
        asyncio.run(crawler.fetch_paginated(client, GHSA))

    assert client.n == 2

def test_nvd_catchup_splits_long_backlog_and_checkpoints_query_end():
    last_success = datetime.now(timezone.utc) - timedelta(days=250)
    src = {**SRC, "last_success": last_success}
    client = FakeClient(total=1, page_size=2000)

    result = json.loads(asyncio.run(crawler.fetch_nvd(client, src)))
    windows = list(dict.fromkeys(client.windows))

    assert len(windows) == 3
    parsed = [
        (_parse_nvd_date(start), _parse_nvd_date(end))
        for start, end in windows
    ]

    for start, end in parsed:
        assert start < end
        assert end - start <= crawler.NVD_DATE_WINDOW

    for previous, following in zip(parsed, parsed[1:]):
        assert previous[1] == following[0]

    assert len(result["vulnerabilities"]) == 3
    assert result["totalResults"] == 3
    assert src["_nvd_checkpoint_at"] == parsed[-1][1]


OTX = {
    "parser": "otx",
    "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
    "source_id": "otx",
}


class OtxClient:
    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    async def get(self, url, params=None, headers=None, timeout=None):
        page = self.calls
        self.calls += 1
        body = {
            "results": [{"id": f"pulse-{page}"}],
            "next": (
                f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={page + 1}"
                if page < self.pages - 1 else None
            ),
        }
        return httpx.Response(
            200, json=body, request=httpx.Request("GET", url)
        )


def test_otx_follows_multiple_pages():
    client = OtxClient(pages=7)
    items = asyncio.run(crawler.fetch_paginated(client, OTX))
    assert len(items) == 7
    assert client.calls == 7


def test_otx_fails_closed_at_page_cap():
    client = OtxClient(pages=crawler.MAX_PAGES + 1)
    with pytest.raises(crawler.IncompleteFetchError, match="MAX_PAGES"):
        asyncio.run(crawler.fetch_paginated(client, OTX))
    assert client.calls == crawler.MAX_PAGES


def test_otx_missing_results_field_is_incomplete():
    class MissingResultsClient:
        async def get(self, url, params=None, headers=None, timeout=None):
            return httpx.Response(
                200,
                json={"next": None},
                request=httpx.Request("GET", url),
            )

    with pytest.raises(crawler.IncompleteFetchError, match="results"):
        asyncio.run(crawler.fetch_paginated(MissingResultsClient(), OTX))


def test_ghsa_missing_advisories_field_is_incomplete():
    class MissingAdvisoriesClient:
        async def get(self, url, params=None, headers=None, timeout=None):
            return httpx.Response(
                200,
                json={"unexpected": []},
                request=httpx.Request("GET", url),
            )

    with pytest.raises(crawler.IncompleteFetchError, match="advisories"):
        asyncio.run(crawler.fetch_paginated(MissingAdvisoriesClient(), GHSA))
