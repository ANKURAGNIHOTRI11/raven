import gzip
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import nvd_feed_index as indexer


def create_test_feed(tmp_path):
    record = {
        "cve": {
            "id": "CVE-2026-12345",
            "sourceIdentifier": "security@example.org",
            "published": "2026-01-01T09:15:51.113",
            "lastModified": "2026-06-17T10:10:55.270",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "fr", "value": "Description française"},
                {"lang": "en", "value": "Example vulnerability. Further details."},
            ],
            "references": [
                {
                    "url": "https://example.org/advisory",
                    "tags": ["Vendor Advisory"],
                },
                {
                    "url": "https://example.org/advisory",
                    "tags": ["Duplicate"],
                },
            ],
        }
    }

    payload = {
        "totalResults": 1,
        "vulnerabilities": [record],
    }

    raw = json.dumps(payload).encode("utf-8")
    compressed = gzip.compress(raw, mtime=0)

    feed = tmp_path / "nvdcve-2.0-2026.json.gz"
    meta = tmp_path / "nvdcve-2.0-2026.meta"
    db = tmp_path / "nvd-2026.sqlite"

    feed.write_bytes(compressed)
    meta.write_text(
        "\n".join([
            "lastModifiedDate:2026-11-01T03:00:26-05:00",
            f"size:{len(raw)}",
            f"gzSize:{len(compressed)}",
            f"sha256:{hashlib.sha256(raw).hexdigest()}",
        ]) + "\n",
        encoding="utf-8",
    )
    return feed, meta, db


def test_builds_sqlite_index_and_extracts_english_metadata(tmp_path):
    feed, meta, db = create_test_feed(tmp_path)

    result = indexer.build_index(feed, meta, db)

    assert result["feed_records"] == 1
    assert result["indexed_records"] == 1
    assert db.is_file()

    with sqlite3.connect(db) as conn:
        row = conn.execute(
            """SELECT cve_id, title, description, published, modified,
                      references_json, source_identifier, vuln_status, raw_json
               FROM nvd_cve"""
        ).fetchone()

        assert row[0] == "CVE-2026-12345"
        assert row[1] == "Example vulnerability."
        assert row[2] == "Example vulnerability. Further details."
        assert row[3] == "2026-01-01T09:15:51.113"
        assert row[4] == "2026-06-17T10:10:55.270"
        assert json.loads(row[5]) == [
            {
                "url": "https://example.org/advisory",
                "tags": ["Vendor Advisory"],
            }
        ]
        assert row[6] == "security@example.org"
        assert row[7] == "Analyzed"
        raw_record = json.loads(row[8])
        assert raw_record["id"] == "CVE-2026-12345"
        assert raw_record["sourceIdentifier"] == "security@example.org"
        assert "descriptions" in raw_record
        assert "references" in raw_record
        assert "published" in raw_record
        assert "lastModified" in raw_record

        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        metadata = dict(conn.execute("SELECT key, value FROM feed_metadata"))
        assert metadata["indexed_records"] == "1"


def test_rejects_bad_feed_checksum_without_creating_index(tmp_path):
    feed, meta, db = create_test_feed(tmp_path)

    text = meta.read_text()
    meta.write_text(text.replace(
        hashlib.sha256(gzip.decompress(feed.read_bytes())).hexdigest(),
        "0" * 64,
    ))

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        indexer.build_index(feed, meta, db)

    assert not db.exists()


def test_rejects_duplicate_cve_identifiers(tmp_path):
    feed, meta, db = create_test_feed(tmp_path)

    raw_payload = gzip.decompress(feed.read_bytes())
    payload = json.loads(raw_payload)
    payload["vulnerabilities"].append(payload["vulnerabilities"][0])
    payload["totalResults"] = len(payload["vulnerabilities"])

    raw = json.dumps(payload).encode()
    compressed = gzip.compress(raw, mtime=0)
    feed.write_bytes(compressed)

    meta.write_text(
        "\n".join([
            "lastModifiedDate:2026-11-01T03:00:26-05:00",
            f"size:{len(raw)}",
            f"gzSize:{len(compressed)}",
            f"sha256:{hashlib.sha256(raw).hexdigest()}",
        ]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(sqlite3.IntegrityError):
        indexer.build_index(feed, meta, db)

    assert not db.exists()
