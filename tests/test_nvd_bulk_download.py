import json, sys
from pathlib import Path
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import nvd_bulk_download as dl

TOTAL = 4500
calls = []

def handler(request: httpx.Request) -> httpx.Response:
    start = int(request.url.params["startIndex"]); calls.append(start)
    n = max(0, min(2000, TOTAL - start))
    return httpx.Response(200, json={"resultsPerPage": n, "startIndex": start, "totalResults": TOTAL,
        "vulnerabilities": [{"cve": {"id": f"CVE-2026-{start+i:05d}"}} for i in range(n)]})

def test_downloads_all_pages_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setenv("RAVEN_NVD_API_KEY", "k" * 36)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert dl.main(["--out", str(tmp_path)], client=client, sleep=lambda s: None) == 0
    assert calls == [0, 2000, 4000]
    ids = [v["cve"]["id"] for p in sorted(tmp_path.glob("page_*.json"))
           for v in json.loads(p.read_text())["vulnerabilities"]]
    assert len(ids) == TOTAL == len(set(ids))
    calls.clear()                                   # second run: nothing left to fetch
    assert dl.main(["--out", str(tmp_path)], client=client, sleep=lambda s: None) == 0
    assert calls == []

def test_bad_key_fails_fast(tmp_path, monkeypatch):
    monkeypatch.setenv("RAVEN_NVD_API_KEY", "bad")
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404, headers={"message": "Invalid apiKey"})))
    import pytest
    with pytest.raises(SystemExit) as e:
        dl.main(["--out", str(tmp_path)], client=client, sleep=lambda s: None)
    assert "404" in str(e.value)
