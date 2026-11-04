from services.enrichment_worker.public_sources import (
    parse_circl_record,
    parse_cve_org_record,
)


def cve_record(cve_id="CVE-2026-12345"):
    return {
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-01-02T00:00:00.000Z",
            "dateUpdated": "2026-02-03T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "title": "Example vulnerability title",
                "descriptions": [
                    {"lang": "fr", "value": "Description en français"},
                    {"lang": "en", "value": "An English source-backed description."},
                ],
                "references": [
                    {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]},
                    {"url": "javascript:alert(1)"},
                ],
            }
        },
    }


def test_cve_org_parser_accepts_exact_cve_json_record():
    source_url = "https://cveawg.mitre.org/api/cve/CVE-2026-12345"
    parsed = parse_cve_org_record(
        cve_record(),
        "CVE-2026-12345",
        source_url=source_url,
    )
    assert parsed["title"] == "Example vulnerability title"
    assert parsed["description"] == "An English source-backed description."
    assert parsed["published"] == "2026-01-02T00:00:00.000Z"
    assert parsed["modified"] == "2026-02-03T00:00:00.000Z"
    assert parsed["sources"] == ["CVE.org CVE Services"]
    assert parsed["source_url"] == source_url
    assert parsed["references"] == [
        {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]}
    ]


def test_cve_org_parser_rejects_wrong_identifier_and_malformed_record():
    assert parse_cve_org_record(
        cve_record("CVE-2026-54321"),
        "CVE-2026-12345",
        source_url="https://cveawg.mitre.org/api/cve/CVE-2026-12345",
    ) == {}
    assert parse_cve_org_record(
        {"cveMetadata": {}, "containers": {}},
        "CVE-2026-12345",
        source_url="https://example.test",
    ) == {}


def test_circl_parser_accepts_nested_cve_record_envelope():
    parsed = parse_circl_record(
        {"vulnerability": cve_record()},
        "CVE-2026-12345",
        source_url="https://vulnerability.circl.lu/api/vulnerability/CVE-2026-12345",
    )
    assert parsed["title"] == "Example vulnerability title"
    assert parsed["sources"] == ["CIRCL Vulnerability-Lookup"]


def test_circl_parser_accepts_osv_shaped_record_with_exact_alias():
    parsed = parse_circl_record(
        {
            "id": "GHSA-abcd-efgh-ijkl",
            "aliases": ["CVE-2026-12345"],
            "summary": "OSV summary",
            "details": "OSV details",
            "published": "2026-01-02T00:00:00Z",
            "modified": "2026-02-03T00:00:00Z",
            "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
        },
        "CVE-2026-12345",
        source_url="https://vulnerability.circl.lu/api/vulnerability/CVE-2026-12345",
    )
    assert parsed["title"] == "OSV summary"
    assert parsed["description"] == "OSV details"
    assert parsed["references"][0]["url"] == "https://example.test/advisory"


def test_circl_parser_rejects_unrelated_record_and_unsafe_reference():
    parsed = parse_circl_record(
        {
            "id": "GHSA-abcd-efgh-ijkl",
            "aliases": ["CVE-2026-99999"],
            "summary": "Wrong CVE",
            "references": [{"url": "file:///etc/passwd"}],
        },
        "CVE-2026-12345",
        source_url="https://vulnerability.circl.lu/api/vulnerability/CVE-2026-12345",
    )
    assert parsed == {}
