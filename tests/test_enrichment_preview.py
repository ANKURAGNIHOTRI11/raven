from datetime import datetime, timezone

from tools.enrichment_preview import build_preview


def test_build_preview_only_proposes_missing_nonconflicting_fields():
    row = {
        "cve_id": "CVE-2026-12345",
        "title": "",
        "description": "",
        "published": None,
        "modified": None,
        "references_json": "[]",
    }
    profile = {
        "title": "Verified title",
        "description": "Verified description",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "references": [{"url": "https://vendor.example/advisory", "tags": []}],
        "sources": ["NVD", "CVE.org CVE Services"],
        "_source_status": {"nvd": True, "cve_org": True},
        "_optional_source_status": {"brave_search": "not_configured"},
        "_lookup_complete": True,
        "_failed_sources": [],
        "_conflicting_fields": {},
        "field_evidence": {"title": [{"source": "CVE.org CVE Services"}]},
        "discovery_leads": [],
    }

    preview = build_preview(row, profile)
    assert preview["proposed_fields"]["title"] == "Verified title"
    assert preview["proposed_fields"]["description"] == "Verified description"
    assert preview["proposed_fields"]["published"] == "2026-01-01T00:00:00+00:00"
    assert preview["proposed_fields"]["modified"] == "2026-01-02T00:00:00+00:00"
    assert preview["proposed_fields"]["references"][0]["url"].startswith("https://")


def test_build_preview_suppresses_conflicts_and_preserves_existing_values():
    row = {
        "cve_id": "CVE-2026-12345",
        "title": "Existing title",
        "description": "",
        "published": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "modified": None,
        "references_json": '[{"url":"https://existing.example"}]',
    }
    profile = {
        "title": "Conflicting new title",
        "description": "New description",
        "published": "2026-01-02T00:00:00Z",
        "modified": "2026-02-01T00:00:00Z",
        "references": [{"url": "https://new.example", "tags": []}],
        "sources": ["NVD"],
        "_source_status": {"nvd": True},
        "_optional_source_status": {"brave_search": "not_configured"},
        "_lookup_complete": True,
        "_failed_sources": [],
        "_conflicting_fields": {"title": [{"source": "NVD"}, {"source": "CVE.org"}]},
        "field_evidence": {},
        "discovery_leads": [],
    }

    preview = build_preview(row, profile)
    proposed = preview["proposed_fields"]
    assert "title" not in proposed
    assert proposed["description"] == "New description"
    assert "published" not in proposed
    assert proposed["modified"] == "2026-02-01T00:00:00+00:00"
    assert "references" not in proposed
    assert preview["existing_fields"]["title"] == "preserved"
