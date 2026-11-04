import asyncio
from datetime import datetime, timezone

import httpx
import pytest

@pytest.fixture(autouse=True)
def no_circl_rate_delay(monkeypatch):
    # Network timing is covered separately; keep mocked HTTP unit tests fast.
    monkeypatch.setenv("RAVEN_CIRCL_REQUEST_DELAY_SECONDS", "0")


from services.enrichment_worker.main import (
    needs_enrichment, parse_ghsa, parse_nvd, parse_osv,
    _can_record_no_match, _get_json, _get_osv, _timestamp, _url_refs,
    fetch_profile,
)


def test_nvd_extracts_english_description_and_references():
    result = parse_nvd({
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-12345",
                "descriptions": [
                    {"lang": "fr", "value": "French"},
                    {"lang": "en", "value": "An example vulnerability."},
                ],
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "references": [{"url": "https://example.org/advisory", "tags": ["Vendor Advisory"]}],
            }
        }]
    }, "CVE-2026-12345")
    assert result["description"] == "An example vulnerability."
    assert result["references"][0]["url"] == "https://example.org/advisory"


def test_ghsa_requires_exact_cve_identifier():
    result = parse_ghsa([{
        "identifiers": [{"type": "CVE", "value": "CVE-2026-12345"}],
        "summary": "Example issue",
        "description": "Detailed issue",
        "references": [{"url": "https://example.org/fix"}],
    }], "CVE-2026-12345")
    assert result["title"] == "Example issue"
    assert parse_ghsa([{"identifiers": [{"value": "CVE-2026-123456"}]}], "CVE-2026-12345") == {}


def test_osv_requires_exact_alias():
    assert parse_osv({"id": "GHSA-abcd-efgh-ijkl", "aliases": ["CVE-2026-12345"],
                      "summary": "Example"}, "CVE-2026-12345")["title"] == "Example"
    assert parse_osv({"id": "CVE-2026-99999", "aliases": [], "summary": "Wrong"},
                     "CVE-2026-12345") == {}


def test_references_only_http_and_deduplicated():
    refs = _url_refs([
        {"url": "https://example.org/a"}, {"url": "https://example.org/a"},
        {"url": "javascript:alert(1)"}, {"url": "file:///etc/passwd"},
    ])
    assert refs == [{"url": "https://example.org/a", "tags": []}]


def test_incomplete_criteria():
    assert needs_enrichment({"cve_id": "CVE-2026-12345", "title": "CVE-2026-12345",
                             "description": "", "published": None, "modified": None,
                             "references_json": []})
    assert not needs_enrichment({"cve_id": "CVE-2026-12345", "title": "Title",
                                 "description": "Details", "published": "2026-01-01",
                                 "modified": "2026-01-02", "references_json": [{"url": "https://x"}]})


def test_timestamp_converts_nvd_iso_string_for_asyncpg():
    result = _timestamp("1999-12-30T05:00:00.000")
    assert isinstance(result, datetime)
    assert result == datetime(1999, 12, 30, 5, 0, tzinfo=timezone.utc)


def test_timestamp_handles_z_and_offset_and_invalid_values():
    assert _timestamp("2026-01-01T00:00:00Z") == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert _timestamp("2026-01-01T02:00:00+02:00") == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert _timestamp("not-a-date") is None
    assert _timestamp(None) is None


def test_needs_enrichment_treats_empty_reference_representations_as_missing():
    complete_row = {
        "cve_id": "CVE-2024-1234",
        "title": "Meaningful vulnerability title",
        "description": "Meaningful description",
        "published": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "modified": datetime(2024, 1, 2, tzinfo=timezone.utc),
    }
    for refs in (None, "", "null", "[]", "{}", [], {}):
        row = {**complete_row, "references_json": refs}
        assert needs_enrichment(row), f"Expected missing references for {refs!r}"


def test_get_osv_fetches_vulnerability_by_id():
    cve_id = "CVE-2024-1234"
    requests = []

    async def handler(request: httpx.Request):
        requests.append(request)
        return httpx.Response(200, json={
            "id": cve_id,
            "aliases": [cve_id],
            "summary": "Sample vulnerability",
        })

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _get_osv(client, cve_id, {})

    result, lookup_completed = asyncio.run(fetch())
    assert lookup_completed is True
    assert result is not None
    assert result["id"] == cve_id
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert str(requests[0].url) == f"https://api.osv.dev/v1/vulns/{cve_id}"


def test_fetch_profile_uses_github_token():
    cve_id = "CVE-2024-1234"
    requests = []

    async def handler(request: httpx.Request):
        requests.append(request)
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_profile(client, cve_id, github_token="test-github-token")

    profile = asyncio.run(fetch())
    github_requests = [r for r in requests if r.url.host == "api.github.com"]
    assert len(github_requests) == 1
    assert github_requests[0].headers["authorization"] == "Bearer test-github-token"
    assert profile["_lookup_complete"] is True
    assert _can_record_no_match(profile) is True


def test_parse_ghsa_uses_nvd_publication_date():
    cve_id = "CVE-1999-0011"
    data = [{
        "cve_id": cve_id,
        "identifiers": [{"type": "CVE", "value": cve_id}],
        "summary": "BIND denial of service vulnerability",
        "description": "A relevant vulnerability description.",
        "published_at": "2022-05-03T03:06:00Z",
        "updated_at": "2023-02-01T05:00:56Z",
        "nvd_published_at": "1999-09-29T00:00:00Z",
        "references": [],
    }]
    result = parse_ghsa(data, cve_id)
    assert result["published"] == "1999-09-29T00:00:00Z"
    assert result["modified"] is None


def test_parse_ghsa_does_not_use_github_dates_as_cve_dates():
    cve_id = "CVE-1999-0011"
    data = [{
        "cve_id": cve_id,
        "identifiers": [{"type": "CVE", "value": cve_id}],
        "summary": "BIND denial of service vulnerability",
        "description": "A relevant vulnerability description.",
        "published_at": "2022-05-03T03:06:00Z",
        "updated_at": "2023-02-01T05:00:56Z",
        "references": [],
    }]
    result = parse_ghsa(data, cve_id)
    assert result["published"] is None
    assert result["modified"] is None


def test_fetch_profile_keeps_partial_data_but_marks_timeout_incomplete():
    cve_id = "CVE-2024-1234"

    async def handler(request: httpx.Request):
        if request.url.host == "services.nvd.nist.gov":
            raise httpx.ReadTimeout("simulated NVD timeout", request=request)
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[{
                "cve_id": cve_id,
                "identifiers": [{"type": "CVE", "value": cve_id}],
                "summary": "Partial GHSA title",
                "description": "Useful description from GHSA.",
                "nvd_published_at": "2024-01-01T00:00:00Z",
                "references": [],
            }])
        if request.url.host in {
            "api.osv.dev",
            "vulnerability.circl.lu",
            "cveawg.mitre.org",
        }:
            return httpx.Response(404)
        raise AssertionError(f"Unexpected host: {request.url.host}")

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_profile(client, cve_id)

    profile = asyncio.run(fetch())
    assert profile["title"] == "Partial GHSA title"
    assert profile["description"] == "Useful description from GHSA."
    assert profile["_lookup_complete"] is False
    assert profile["_failed_sources"] == ["nvd"]
    assert _can_record_no_match(profile) is False


def test_no_match_cooldown_requires_all_source_lookups_to_complete():
    assert _can_record_no_match({"_lookup_complete": True}) is True
    assert _can_record_no_match({"_lookup_complete": False}) is False
    assert _can_record_no_match({}) is False


def test_get_json_distinguishes_not_found_from_http_failures():
    async def run_status(status):
        async def handler(request: httpx.Request):
            if status == 200:
                return httpx.Response(200, content=b"not-json")
            return httpx.Response(status)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _get_json(client, "https://example.test/source")

    missing, missing_ok = asyncio.run(run_status(404))
    _, rate_limit_ok = asyncio.run(run_status(429))
    _, server_error_ok = asyncio.run(run_status(503))
    _, invalid_json_ok = asyncio.run(run_status(200))
    assert missing is None and missing_ok is True
    assert rate_limit_ok is False
    assert server_error_ok is False
    assert invalid_json_ok is False

    async def run_null_json():
        async def handler(request: httpx.Request):
            return httpx.Response(200, json=None)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _get_json(client, "https://example.test/source")

    null_data, null_completed = asyncio.run(run_null_json())
    assert null_data is None
    assert null_completed is False


def test_get_osv_distinguishes_not_found_from_service_failure():
    async def run_status(status):
        async def handler(request: httpx.Request):
            return httpx.Response(status)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await _get_osv(client, "CVE-2024-1234", {})

    missing, missing_ok = asyncio.run(run_status(404))
    failed, failed_ok = asyncio.run(run_status(503))
    assert missing is None and missing_ok is True
    assert failed is None and failed_ok is False


def test_fetch_profile_rejects_unexpected_nvd_and_ghsa_response_shapes():
    cve_id = "CVE-2024-1234"

    async def handler(request: httpx.Request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"unexpected": "schema"})
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"unexpected": "schema"})
        if request.url.host in {
            "api.osv.dev",
            "vulnerability.circl.lu",
            "cveawg.mitre.org",
        }:
            return httpx.Response(404)
        raise AssertionError(f"Unexpected host: {request.url.host}")

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_profile(client, cve_id)

    profile = asyncio.run(fetch())
    assert profile["_lookup_complete"] is False
    assert profile["_failed_sources"] == ["nvd", "ghsa"]
    assert _can_record_no_match(profile) is False



def test_candidate_query_supports_fresh_database_without_audit_table():
    from services.enrichment_worker.main import _candidate_query

    query = _candidate_query(False)
    assert "FROM vulnerabilities" in query
    assert "vulnerability_enrichment_audit" not in query


def test_candidate_query_applies_cooldown_to_all_recorded_apply_attempts():
    from services.enrichment_worker.main import _candidate_query

    query = _candidate_query(True)
    assert "vulnerability_enrichment_audit" in query
    assert "completed_at >= now() - INTERVAL '7 days'" in query
    assert "applied IS FALSE" not in query


def test_parsers_ignore_malformed_nested_feed_shapes():
    cve_id = "CVE-2026-12345"
    nvd = parse_nvd({
        "vulnerabilities": [
            {"cve": None},
            {"cve": {"id": cve_id, "descriptions": None, "references": None}},
        ]
    }, cve_id)
    assert nvd["description"] is None
    assert nvd["references"] == []
    assert parse_ghsa([{"identifiers": None}], cve_id) == {}
    assert parse_osv({"id": "GHSA-abcd-efgh-ijkl", "aliases": None}, cve_id) == {}


def test_invalid_source_timestamps_do_not_count_as_fillable_dates():
    from services.enrichment_worker.main import _timestamp

    assert _timestamp("not-a-timestamp") is None



def test_systemd_units_keep_dry_run_and_live_apply_separate():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    dry_run = (root / "deploy/systemd/raven-enrichment-worker.service").read_text()
    live_apply = (root / "deploy/systemd/raven-enrichment-apply@.service").read_text()

    assert "--limit 25" in dry_run
    assert "--apply" not in dry_run
    assert "--limit %i --apply" in live_apply
    for unit in (dry_run, live_apply):
        assert "NoNewPrivileges=true" in unit
        assert "ProtectSystem=strict" in unit
        assert "ProtectHome=true" in unit



def test_fetch_profile_uses_public_registry_fallbacks_and_records_evidence():
    cve_id = "CVE-2026-12345"
    cve_record = {
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-01-02T00:00:00Z",
            "dateUpdated": "2026-02-03T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": "Public fallback title",
                "descriptions": [{"lang": "en", "value": "Public fallback description."}],
                "references": [{"url": "https://vendor.example/advisory"}],
            }
        },
    }

    async def handler(request: httpx.Request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"vulnerabilities": []})
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        if request.url.host == "api.osv.dev":
            return httpx.Response(404)
        if request.url.host == "vulnerability.circl.lu":
            return httpx.Response(200, json={"vulnerability": cve_record})
        if request.url.host == "cveawg.mitre.org":
            return httpx.Response(200, json=cve_record)
        raise AssertionError(f"Unexpected host: {request.url.host}")

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_profile(client, cve_id)

    profile = asyncio.run(fetch())
    assert profile["title"] == "Public fallback title"
    assert profile["description"] == "Public fallback description."
    assert profile["_lookup_complete"] is True
    assert profile["_failed_sources"] == []
    assert "CIRCL Vulnerability-Lookup" in profile["sources"]
    assert "CVE.org CVE Services" in profile["sources"]
    assert len(profile["field_evidence"]["title"]) == 2
    assert profile["_conflicting_fields"] == {}


def test_fetch_profile_marks_disagreement_between_public_sources():
    cve_id = "CVE-2026-12345"
    circl_record = {
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Description from CIRCL."}],
                "references": [],
            }
        },
    }

    async def handler(request: httpx.Request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "Different description from NVD."}],
                    "references": [],
                }
            }]})
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[])
        if request.url.host == "api.osv.dev":
            return httpx.Response(404)
        if request.url.host == "vulnerability.circl.lu":
            return httpx.Response(200, json=circl_record)
        if request.url.host == "cveawg.mitre.org":
            return httpx.Response(404)
        raise AssertionError(f"Unexpected host: {request.url.host}")

    async def fetch():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await fetch_profile(client, cve_id)

    profile = asyncio.run(fetch())
    assert "description" in profile["_conflicting_fields"]
    assert len(profile["_conflicting_fields"]["description"]) == 2
