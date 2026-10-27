import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

NORMALIZER_DIR = Path(__file__).resolve().parents[1] / "services" / "normalizer"
sys.path.insert(0, str(NORMALIZER_DIR))

from main import Rejected, SourceClass, _validate_timestamp, merge


NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def test_nanosecond_iso_timestamp_is_accepted():
    _validate_timestamp(
        "2026-09-10T03:50:22.781448235Z",
        "modified",
        NOW,
    )


def test_standard_iso_timestamp_is_accepted():
    _validate_timestamp(
        "2026-09-10T03:50:22.781448Z",
        "modified",
        NOW,
    )


def test_malformed_timestamp_is_still_rejected():
    with pytest.raises(Rejected):
        _validate_timestamp("not-a-timestamp", "modified", NOW)


def test_implausibly_future_timestamp_is_still_rejected():
    with pytest.raises(Rejected):
        _validate_timestamp(
            "2026-10-24T00:00:00.000000000Z",
            "modified",
            NOW,
        )


def test_stale_snapshot_preserves_current_scalars():
    from raven_common.models import SourceClass

    current_modified = datetime(2026, 9, 30, tzinfo=timezone.utc)
    existing = {
        "cve_id": "CVE-2025-1234",
        "title": "Current title",
        "description": "Current description",
        "published": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "modified": current_modified,
        "cvss_base": 9.8,
        "cvss_vector": "current-vector",
        "cvss_version": "3.1",
        "severity": "critical",
        "kev": True,
        "epss_score": 0.9,
        "cwe_ids": ["CWE-79"],
        "affected_packages": ["current-package"],
        "references": [{"url": "https://current.example", "tags": []}],
        "provenance": ["current-doc"],
        "source_trust": 0.75,
    }
    incoming = {
        "cve_id": "CVE-2025-1234",
        "title": "Stale title",
        "description": "Stale description",
        "published": "2024-01-01T00:00:00Z",
        "modified": "2026-09-10T03:50:22.781448235Z",
        "cvss_base": 0.0,
        "cvss_vector": None,
        "cvss_version": "3.1",
        "severity": "none",
        "kev": False,
        "epss_score": 0.1,
        "cwe_ids": ["CWE-89"],
        "affected_packages": ["stale-package"],
        "references": [{"url": "https://stale.example", "tags": []}],
        "provenance": ["stale-doc"],
    }

    result = merge(existing, incoming, 0.99, SourceClass.AUTHORITATIVE)

    assert result["title"] == "Current title"
    assert result["description"] == "Current description"
    assert result["published"] == existing["published"]
    assert result["modified"] == current_modified
    assert result["cvss_base"] == 9.8
    assert result["cvss_vector"] == "current-vector"
    assert result["severity"] == "critical"
    assert result["kev"] is True
    assert result["epss_score"] == 0.9

    assert set(result["cwe_ids"]) == {"CWE-79", "CWE-89"}
    assert set(result["affected_packages"]) == {
        "current-package", "stale-package"
    }
    assert {r["url"] for r in result["references"]} == {
        "https://current.example", "https://stale.example"
    }
    assert set(result["provenance"]) == {"current-doc", "stale-doc"}


def test_newer_snapshot_can_update_current_scalars():
    from raven_common.models import SourceClass

    existing = {
        "cve_id": "CVE-2025-2345",
        "title": "Older title",
        "description": "Older description",
        "modified": datetime(2026, 9, 10, tzinfo=timezone.utc),
        "source_trust": 0.75,
        "provenance": ["older-doc"],
    }
    incoming = {
        "cve_id": "CVE-2025-2345",
        "title": "Newer title",
        "description": "Newer description",
        "modified": "2026-10-01T00:00:00Z",
        "provenance": ["newer-doc"],
    }

    result = merge(existing, incoming, 0.90, SourceClass.AUTHORITATIVE)

    assert result["title"] == "Newer title"
    assert result["description"] == "Newer description"
    assert _validate_timestamp(
        result["modified"], "modified",
        datetime(2026, 10, 21, tzinfo=timezone.utc),
    ) is None
    assert set(result["provenance"]) == {"older-doc", "newer-doc"}


def test_newer_modified_timestamp_wins_even_with_lower_trust():
    existing = {
        "cve_id": "CVE-2026-12345",
        "title": "Existing trusted title",
        "modified": datetime(2026, 6, 9, tzinfo=timezone.utc),
        "source_trust": 0.95,
    }

    incoming = {
        "cve_id": "CVE-2026-12345",
        "title": "Lower-trust incoming title",
        "modified": "2026-06-10T00:00:00Z",
    }

    result = merge(
        existing,
        incoming,
        trust=0.45,
        klass=SourceClass.AUTHORITATIVE,
    )

    # Freshness must win for modified, independently of source trust.
    assert result["modified"] == incoming["modified"]

    # Trust-based arbitration must still protect descriptive fields.
    assert result["title"] == "Existing trusted title"

    # Lower-trust input must not lower the stored trust score.
    assert result["source_trust"] == 0.95
