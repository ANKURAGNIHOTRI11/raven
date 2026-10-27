"""Per-source parsers. Each returns a list of partial vulnerability dicts in
RAVEN's intermediate shape; the normalization service is what turns these into
contract-valid NormalizedVulnerability records."""
from __future__ import annotations

import csv
import gzip
import html
import io
import re
import xml.etree.ElementTree as ET
from typing import Any

SEVERITY_BY_SCORE = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]


def severity_of(score: float) -> str:
    for threshold, label in SEVERITY_BY_SCORE:
        if score >= threshold:
            return label
    return "none"


def parse_nvd(payload: dict[str, Any]) -> list[dict]:
    out: list[dict] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
        metrics = cve.get("metrics", {})
        base, vector, version = 0.0, None, "3.1"
        for key in (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ):
            if metrics.get(key):
                data = metrics[key][0].get("cvssData", {})
                base = float(data.get("baseScore", 0.0))
                vector = data.get("vectorString")
                version = str(data.get("version", version))
                break
        cwes: list[str] = []
        for weak in cve.get("weaknesses", []):
            for d in weak.get("description", []):
                if str(d.get("value", "")).startswith("CWE-"):
                    cwes.append(d["value"])
        cpes: list[str] = []

        def collect_cpes(node: dict[str, Any]) -> None:
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpes.append(match["criteria"])

            for child in node.get("children", []):
                collect_cpes(child)

        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                collect_cpes(node)
        out.append({
            "cve_id": cve_id,
            "title": "",
            "description": descs[0] if descs else "",
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "cvss_base": base,
            "cvss_vector": vector,
            "cvss_version": version,
            "severity": severity_of(base),
            "cwe_ids": sorted(set(cwes)),
            "cpe_uris": sorted(set(cpes))[:200],
            "references": [{"url": r["url"], "tags": r.get("tags", [])}
                           for r in cve.get("references", []) if r.get("url")][:40],
        })
    return out


def parse_kev(payload: dict[str, Any]) -> list[dict]:
    out = []
    for v in payload.get("vulnerabilities", []):
        if not v.get("cveID"):
            continue
        out.append({
            "cve_id": v["cveID"],
            "title": v.get("vulnerabilityName", v["cveID"]),
            "description": v.get("shortDescription", ""),
            "kev": True,
            "kev_due_date": v.get("dueDate"),
            "exploit_maturity": "weaponized",
            "vendor_advisories": [v["notes"]] if v.get("notes") else [],
        })
    return out


def parse_epss(raw: bytes) -> list[dict]:
    """EPSS ships a gzipped CSV with a comment header line."""
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    text = data.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    out = []
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        out.append({
            "cve_id": cve,
            "epss_score": float(row.get("epss") or 0.0),
            "epss_percentile": float(row.get("percentile") or 0.0),
        })
    return out


def parse_osv(payload: dict[str, Any]) -> list[dict]:
    out = []
    for vuln in payload.get("vulns", payload.get("results", [])):
        if isinstance(vuln, dict) and vuln.get("id"):
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln["id"])
            pkgs = [
                f"{a['package'].get('ecosystem','')}:{a['package'].get('name','')}"
                for a in vuln.get("affected", []) if a.get("package")
            ]
            out.append({
                "cve_id": cve_id,
                "title": vuln.get("summary", cve_id),
                "description": vuln.get("details", "")[:8000],
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
                "affected_packages": sorted(set(pkgs))[:100],
                "references": [{"url": r["url"], "tags": [r.get("type", "")]}
                               for r in vuln.get("references", []) if r.get("url")][:30],
            })
    return out


def parse_ghsa(payload: Any) -> list[dict]:
    items = payload if isinstance(payload, list) else payload.get("advisories", [])
    out = []
    for adv in items:
        cve_id = adv.get("cve_id") or adv.get("ghsa_id")
        if not cve_id:
            continue
        score = float((adv.get("cvss") or {}).get("score") or 0.0)
        pkgs = [
            f"{v['package'].get('ecosystem','')}:{v['package'].get('name','')}"
            for v in adv.get("vulnerabilities", []) if v.get("package")
        ]
        out.append({
            "cve_id": cve_id,
            "title": adv.get("summary", cve_id),
            "description": (adv.get("description") or "")[:8000],
            "published": adv.get("published_at"),
            "modified": adv.get("updated_at"),
            "cvss_base": score,
            "cvss_vector": (adv.get("cvss") or {}).get("vector_string"),
            "severity": adv.get("severity", severity_of(score)),
            "cwe_ids": [c["cwe_id"] for c in adv.get("cwes", []) if c.get("cwe_id")],
            "affected_packages": sorted(set(pkgs))[:100],
            "references": [{"url": u, "tags": ["ghsa"]} for u in adv.get("references", [])][:30],
        })
    return out


def parse_redhat(payload: Any) -> list[dict]:
    items = payload if isinstance(payload, list) else []
    out = []
    for adv in items:
        cve_id = adv.get("CVE")
        if not cve_id:
            continue
        bugzilla_description = " ".join(
            str(adv.get("bugzilla_description") or "").split()
        )
        out.append({
            "cve_id": cve_id,
            "title": bugzilla_description[:1000],
            "description": (adv.get("bugzilla_description") or "")[:4000],
            "cvss_base": float(adv.get("cvss3_score") or 0.0),
            "cvss_vector": adv.get("cvss3_scoring_vector"),
            "severity": (adv.get("severity") or "none").lower(),
            "cwe_ids": re.findall(r"CWE-\d+", adv.get("CWE") or ""),
            "affected_packages": adv.get("affected_packages", [])[:100],
            "vendor_advisories": adv.get("advisories", [])[:20],
            "published": adv.get("public_date"),
        })
    return out


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


# Full-text handling limits. A feed item's body is untrusted text of unbounded
# size, so what we read from it and how many records one item may produce are
# both capped.
RSS_BODY_LIMIT = 400_000     # characters of one item's body that are searched
RSS_MAX_CVES_PER_ITEM = 100  # a roundup naming hundreds of CVEs must not flood the bus
RSS_CONTEXT_WINDOW = 200     # characters either side of a mention that are considered
_EXPLOIT_RE = re.compile(r"\b(exploited|in the wild|poc)\b", re.I)
_FEED_ROOTS = frozenset({"rss", "feed", "RDF"})   # RSS 2.0 / Atom / RSS 1.0


class NotAFeed(ValueError):
    """The document is not an RSS/Atom feed - typically an HTML challenge,
    consent or moved-page response served with HTTP 200. Raised rather than
    returning [] so the crawler records a failure (quarantine excerpt, failure
    count, circuit breaker) instead of logging a healthy harvest of 0 records,
    which is indistinguishable from a feed that simply names no CVEs."""


def _peek(raw: bytes, n: int = 60) -> str:
    return " ".join(raw[:n].decode("utf-8", "replace").split())


def _plain(markup: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(markup))).strip()


def _mention_windows(text: str, cve_id: str):
    for m in re.finditer(re.escape(cve_id), text):
        yield text[max(0, m.start() - RSS_CONTEXT_WINDOW): m.end() + RSS_CONTEXT_WINDOW]


def parse_rss(raw: bytes) -> list[dict]:
    """Media and PSIRT RSS/Atom. Only CVE mentions are lifted; the prose is kept
    as low-trust context, never as an authoritative field.

    The CVE search covers the item's *full text* (RSS content:encoded, Atom
    <content>), not just the teaser: Ghost and WordPress blogs put only a short
    summary in <description>, so searching that alone missed every CVE named in
    the body. Exploit maturity is judged from the text around each mention, not
    from the whole article, so one "exploited in the wild" in a long roundup
    does not mark every CVE in it.
    """
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise NotAFeed(f"not valid XML ({str(exc)[:60]}); starts {_peek(raw)!r}") from exc
    root_name = root.tag.split("}")[-1]
    if root_name not in _FEED_ROOTS:
        raise NotAFeed(f"root element <{root_name[:30]}> is not a feed; starts {_peek(raw)!r}")
    out = []
    for item in root.iter():
        if item.tag.split("}")[-1] not in ("item", "entry"):
            continue

        def text(tag: str) -> str:
            for child in item:
                if child.tag.split("}")[-1] == tag:
                    # itertext() so XHTML content with child elements is read in full
                    return "".join(child.itertext()).strip()
            return ""

        def link() -> str:
            for child in item:
                if child.tag.split("}")[-1] != "link":
                    continue
                href = (child.get("href") or "").strip()      # Atom
                if href and child.get("rel", "alternate") == "alternate":
                    return href
                if (child.text or "").strip():                 # RSS
                    return child.text.strip()
            return ""

        title = text("title")
        teaser = _plain(text("description") or text("summary"))
        body = _plain(text("encoded") or text("content"))[:RSS_BODY_LIMIT]
        searchable = f"{title} {teaser} {body}"
        url = link()
        head = f"{title} {teaser}"
        for cve_id in sorted(set(CVE_RE.findall(searchable)))[:RSS_MAX_CVES_PER_ITEM]:
            windows = list(_mention_windows(searchable, cve_id))
            description = teaser[:1500]
            if cve_id not in head and windows:
                # Named only in the body: keep a short excerpt around it as context.
                description = f"{description} ... {windows[0]}".strip()
            out.append({
                "cve_id": cve_id,
                "title": title[:300],
                "description": description[:2000],
                "references": [{"url": url, "tags": ["news"]}] if url else [],
                "exploit_maturity": "poc" if any(_EXPLOIT_RE.search(w) for w in windows) else "none",
            })
    return out


def parse_otx(payload: Any) -> list[dict]:
    """AlienVault OTX pulses are analyst write-ups, not authoritative advisories -
    treat them like RSS: lift explicit CVE mentions only, keep the narrative as
    low-trust context, never as an authoritative field. Community-submitted, so
    the trust score for this source sits at the floor (see sources seed)."""
    items = payload if isinstance(payload, list) else payload.get("results", [])
    out = []
    for pulse in items:
        if not isinstance(pulse, dict):
            continue
        name = pulse.get("name", "") or ""
        desc = pulse.get("description", "") or ""
        tags = " ".join(pulse.get("tags", []) or [])
        blob = f"{name} {desc} {tags}"
        cves = sorted(set(CVE_RE.findall(blob)))
        if not cves:
            continue
        refs = [{"url": r, "tags": ["otx"]} for r in (pulse.get("references") or []) if r][:20]
        maturity = ("poc" if re.search(r"\b(exploited|in the wild|weaponi[sz]ed|poc)\b", blob, re.I)
                    else "none")
        clean_desc = re.sub(r"\s+", " ", desc).strip()[:4000]
        for cve_id in cves:
            out.append({
                "cve_id": cve_id,
                "title": (name[:300] or cve_id),
                "description": clean_desc,
                "references": refs,
                "exploit_maturity": maturity,
            })
    return out


PARSERS = {
    "nvd": ("json", parse_nvd),
    "kev": ("json", parse_kev),
    "epss": ("bytes", parse_epss),
    "osv": ("json", parse_osv),
    "ghsa": ("json", parse_ghsa),
    "redhat": ("json", parse_redhat),
    "msrc": ("json", lambda p: []),
    "rss": ("bytes", parse_rss),
    "otx": ("json", parse_otx),
    "cmdb": ("json", lambda p: []),
}
