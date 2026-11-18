import gzip
import hashlib

import httpx
import pytest

from tools import nvd_feed_sync as sync


def make_feed():
    payload = b'{"vulnerabilities":[],"totalResults":0}'
    compressed = gzip.compress(payload, mtime=0)
    meta = (
        "lastModifiedDate:2026-11-01T03:00:26-05:00\n"
        f"size:{len(payload)}\n"
        f"gzSize:{len(compressed)}\n"
        f"sha256:{hashlib.sha256(payload).hexdigest().upper()}\n"
    )
    return payload, compressed, meta


def test_parse_meta_preserves_timezone_colons():
    _, _, text = make_feed()
    parsed = sync.parse_meta(text)

    assert parsed["lastModifiedDate"] == "2026-11-01T03:00:26-05:00"
    assert parsed["sha256"] == hashlib.sha256(
        b'{"vulnerabilities":[],"totalResults":0}'
    ).hexdigest()


def test_downloads_feed_and_reuses_verified_copy(tmp_path):
    _, compressed, meta = make_feed()
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith(".meta"):
            return httpx.Response(200, text=meta)
        if request.url.path.endswith(".json.gz"):
            assert request.headers["accept"] == "*/*"
            return httpx.Response(200, content=compressed)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    assert sync.main(
        ["--year", "2026", "--out", str(tmp_path)],
        client=client,
    ) == 0

    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    meta_file = tmp_path / "nvdcve-2.0-2026.meta"

    assert feed.is_file()
    assert meta_file.read_text() == meta
    assert sync.verify_gzip(feed, sync.parse_meta(meta))
    assert len(calls) == 2

    # The next run checks metadata but reuses the verified feed.
    assert sync.main(
        ["--year", "2026", "--out", str(tmp_path)],
        client=client,
    ) == 0

    assert len(calls) == 3
    assert calls[-1].endswith(".meta")
    assert not list(tmp_path.glob("*.part"))
    assert not list(tmp_path.glob("*.new"))

    client.close()


def test_rejects_bad_uncompressed_checksum(tmp_path):
    _, compressed, meta = make_feed()
    bad_meta = meta.replace(
        hashlib.sha256(b'{"vulnerabilities":[],"totalResults":0}').hexdigest().upper(),
        "0" * 64,
    )

    def handler(request):
        if request.url.path.endswith(".meta"):
            return httpx.Response(200, text=bad_meta)
        return httpx.Response(200, content=compressed)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    with pytest.raises(SystemExit, match="verification failed"):
        sync.main(
            ["--year", "2026", "--out", str(tmp_path)],
            client=client,
        )

    assert not (tmp_path / "nvdcve-2.0-2026.json.gz").exists()
    assert not (tmp_path / "nvdcve-2.0-2026.meta").exists()
    client.close()


def test_rejects_invalid_year(tmp_path):
    with pytest.raises(SystemExit):
        sync.main(["--year", "2001", "--out", str(tmp_path)])
