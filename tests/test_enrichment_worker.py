from services.enrichment_worker.main import needs_enrichment, parse_ghsa, parse_nvd, parse_osv, _url_refs


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
