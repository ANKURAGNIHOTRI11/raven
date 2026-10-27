from raven_common.models import Asset, AttackPath, GraphSignal, NormalizedVulnerability
from scoring import score


def vuln(**kw):
    base = dict(cve_id="CVE-2024-0001", cvss_base=7.5, severity="high",
                epss_percentile=0.5, source_trust=0.98, ingest_confidence=0.9,
                cpe_uris=["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"])
    base.update(kw)
    return NormalizedVulnerability(**base)


def asset(**kw):
    base = dict(asset_id="a1", criticality=4, environment="prod", internet_exposed=True)
    base.update(kw)
    return Asset(**base)


def test_kev_outranks_a_higher_cvss_without_exploitation():
    known_exploited = score(vuln(cvss_base=6.5, kev=True, exploit_maturity="weaponized",
                                 epss_percentile=0.97), asset(), None)
    theoretical = score(vuln(cvss_base=9.8, epss_percentile=0.05), asset(), None)
    assert known_exploited.score > theoretical.score


def test_compensating_controls_pull_the_score_down():
    bare = score(vuln(), asset(), None)
    defended = score(vuln(), asset(compensating_controls=["waf", "segmentation", "edr"]), None)
    assert defended.score < bare.score


def test_chain_signal_escalates_a_medium_finding():
    quiet = score(vuln(cvss_base=5.0, severity="medium"), asset(criticality=5), None)
    chained = score(
        vuln(cvss_base=5.0, severity="medium"),
        asset(criticality=5),
        GraphSignal(cve_id="CVE-2024-0001", asset_id="a1", reachability=0.8, blast_radius=9,
                    chain_score=0.9,
                    paths=[AttackPath(path_id="p", nodes=["login01", "CVE-2024-0001", "nfs01"],
                                      entry_point="login01", target_asset="nfs01",
                                      feasibility=0.8, impact=0.9, is_sleeper_chain=True)]),
    )
    assert chained.score > quiet.score + 10
    assert any(e.label == "Sleeper chain" for e in chained.evidence)


def test_low_confidence_widens_the_interval():
    thin = score(vuln(cvss_base=0.0, epss_percentile=0.0, source_trust=0.4,
                      ingest_confidence=0.3, cpe_uris=[]), asset(), None)
    assert thin.ci_high - thin.ci_low > 20
    assert thin.confidence < 0.6


def test_adversarial_flag_halves_confidence():
    clean = score(vuln(), asset(), GraphSignal(cve_id="c", asset_id="a1"))
    flagged = score(vuln(), asset(), GraphSignal(cve_id="c", asset_id="a1", adversarial_flag=True))
    assert flagged.confidence < clean.confidence


def test_every_score_carries_an_evidence_trail():
    s = score(vuln(), asset(), None)
    assert len(s.evidence) >= 10
    assert all(e.label and e.source for e in s.evidence)
