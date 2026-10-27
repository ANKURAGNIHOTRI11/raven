"""Loads the REAL normalizer gate (screen -> merge -> contract) without its I/O,
and holds the corpus used to measure malformed-record leakage.

Nothing here is a copy of the gate logic: adversarial_screen, merge and the
NormalizedVulnerability contract are imported from services/normalizer/main.py.
Only the heavyweight, side-effecting parts of that module (bootstrap() and the
BERT enricher, both constructed at import time) are stubbed.

Outcomes, for one record:
  quarantined       the gate rejected it AND recorded why (visible, auditable)
  dropped_silently  it failed, but only a log line says so - no quarantine row
  accepted          it went through to persist()

For a malformed record the only acceptable outcome is "quarantined":
"accepted" is leakage, "dropped_silently" is data that vanishes with no trace.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("aiokafka")
pytest.importorskip("asyncpg")

import raven_common.runtime as _rt  # noqa: E402
from raven_common.models import RawDocument, Reference, SourceClass  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class _Log:
    def __getattr__(self, name):
        return lambda *a, **k: None


def load_normalizer():
    _rt.bootstrap = lambda service: (types.SimpleNamespace(classifier_model="stub"), _Log())
    stub = types.ModuleType("enrich")
    stub.Enricher = lambda *a, **k: object()
    sys.modules["enrich"] = stub
    spec = importlib.util.spec_from_file_location("normalizer_main", ROOT / "services/normalizer/main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


N = load_normalizer()


@dataclass(frozen=True)
class Outcome:
    kind: str
    detail: str = ""


def run_gate(rec: dict, klass: SourceClass = SourceClass.AUTHORITATIVE, trust: float = 0.9) -> Outcome:
    """The gate stages of normalizer.handle(), minus I/O."""
    doc = RawDocument(doc_id="t", source_id="t", source_class=klass, url="https://t.test",
                      content_sha256="0" * 8, content_type="x", object_key="k", payload=rec, trust=trust)
    rec = dict(doc.payload)
    try:
        N.adversarial_screen(rec, doc)
    except N.Rejected as rej:
        return Outcome("quarantined", rej.reason)
    except Exception as exc:                       # main() logs this and moves on
        return Outcome("dropped_silently", f"screen:{type(exc).__name__}")
    try:
        rec["provenance"] = ["t"]
        cve_id = str(rec["cve_id"]).upper()
        merged = N.merge(None, rec, trust, klass)
        merged["cve_id"] = cve_id
        merged["references"] = [
            Reference.model_validate(r).model_dump() if isinstance(r, dict) else {"url": str(r)}
            for r in (merged.get("references") or [])
        ][:60]
        N.NormalizedVulnerability.model_validate(merged)
    except Exception as exc:                       # post_merge_invalid / normalize_failed
        return Outcome("dropped_silently", f"contract:{type(exc).__name__}")
    return Outcome("accepted")


def base(**over) -> dict:
    rec = {
        "cve_id": "CVE-2024-12345", "title": "Example flaw",
        "description": "A flaw in Example allows remote attackers to read files.",
        "cvss_base": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_version": "3.1", "severity": "high", "cwe_ids": ["CWE-22"], "cpe_uris": [],
        "references": [{"url": "https://example.test/advisory", "tags": []}],
        "epss_score": 0.2, "epss_percentile": 0.5, "exploit_maturity": "none",
    }
    rec.update(over)
    return rec


XSS = "<script>alert(1)</script>"

# (name, record) - every one of these is malformed or hostile and must be QUARANTINED.
MALFORMED = [
    # identifiers
    ("id_too_short", base(cve_id="CVE-24-1")),
    ("id_empty", base(cve_id="")),
    ("id_missing", {k: v for k, v in base().items() if k != "cve_id"}),
    ("id_integer", base(cve_id=12345)),
    ("id_path_traversal", base(cve_id="../../etc/passwd")),
    ("id_sql_fragment", base(cve_id="CVE-2024-1234'; DROP TABLE vulnerabilities;--")),
    ("id_unicode_hyphen", base(cve_id="CVE\u20112024\u20111234")),
    ("id_fullwidth_digits", base(cve_id="CVE-\uff12\uff10\uff12\uff14-1234")),
    ("id_10k_chars", base(cve_id="CVE-2024-" + "1" * 10000)),
    # plausibility
    ("year_before_cve_programme", base(cve_id="CVE-1998-1234")),
    ("year_in_the_future", base(cve_id="CVE-2099-1234")),
    ("published_in_the_future", base(published="2099-01-01T00:00:00")),
    # numbers
    ("cvss_above_10", base(cvss_base=10.1)),
    ("cvss_negative", base(cvss_base=-0.1)),
    ("cvss_nan", base(cvss_base=float("nan"))),
    ("cvss_not_numeric", base(cvss_base="N/A")),
    ("cvss4_above_10", base(cvss4_base=11)),
    ("epss_above_1", base(epss_score=1.5)),
    ("epss_percentile_above_1", base(epss_percentile=5.0)),
    ("severity_not_in_enum", base(severity="apocalyptic")),
    # size
    ("description_250k", base(description="x" * 250_000)),
    ("title_250k", base(title="x" * 250_000)),
    ("cpe_flood", base(cpe_uris=[f"cpe:2.3:a:v:p{i}:*:*:*:*:*:*:*:*" for i in range(6000)])),
    # active content in description
    ("desc_script_tag", base(description=XSS)),
    ("desc_script_uppercase_spaced", base(description="< SCRIPT >alert(1)</SCRIPT>")),
    ("desc_img_onerror", base(description="<img src=x onerror=alert(1)>")),
    ("desc_javascript_uri", base(description="click javascript:alert(1)")),
    ("desc_data_html_uri", base(description="see data:text/html,<b>x</b>")),
    ("desc_svg_onload", base(description="<svg onload=alert(1)>")),
    ("desc_body_onload", base(description="<body onload=alert(1)>")),
    ("desc_iframe", base(description="<iframe src=//evil.test></iframe>")),
    ("desc_entity_encoded_js_uri", base(description="&#106;avascript:alert(1)")),
    # the same payloads in fields other than description
    ("title_script_tag", base(title=XSS)),
    ("title_svg_onload", base(title="<svg onload=alert(1)>")),
    ("reference_javascript_scheme", base(references=[{"url": "javascript:alert(1)", "tags": []}])),
    ("reference_data_scheme", base(references=[{"url": "data:text/html;base64,PHNjcmlwdD4=", "tags": []}])),
    ("reference_file_scheme", base(references=[{"url": "file:///etc/passwd", "tags": []}])),
    # structure
    ("reference_without_url", base(references=[{"tags": []}])),
    ("cwe_ids_is_a_string", base(cwe_ids="CWE-79")),
    ("description_is_an_object", base(description={"$ne": None})),
    ("description_with_nul_byte", base(description="abc\x00def")),
]

# Legitimate records that must NOT be rejected (false-positive control).
LEGIT = [
    ("plain_nvd_record", base()),
    ("seven_digit_cve", base(cve_id="CVE-2024-1234567")),
    ("lowercase_id", base(cve_id="cve-2024-12345")),
    ("whitespace_padded_id", base(cve_id="  CVE-2024-12345 ")),
    ("ghsa_id", base(cve_id="GHSA-abcd-efgh-ijkl")),
    ("non_latin_description", base(description="リモートの攻撃者が任意のファイルを読み取れる脆弱性")),
    ("math_in_description", base(description="Triggered when the buffer length < 5 and index > 2.")),
    ("xss_advisory_quoting_markup", base(description="XSS via the <script> tag in the title field allows code execution.")),
    ("advisory_mentioning_javascript_uri", base(description="The link handler accepts javascript: URIs in href attributes.")),
]
