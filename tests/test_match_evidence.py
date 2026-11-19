import asyncio
from types import SimpleNamespace

from ingest_gate_harness import N

CVE_OPENSSL = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
HOST_OPENSSL = "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"


def test_exact_cpe_is_strongest():
    assert N.match_evidence([HOST_OPENSSL], [HOST_OPENSSL]) == "cpe_exact"


def test_same_vendor_and_product_any_version():
    assert N.match_evidence([CVE_OPENSSL], [HOST_OPENSSL]) == "cpe_product"


def test_same_vendor_different_product_is_not_a_match():
    other = "cpe:2.3:a:openssl:libressl:3.0:*:*:*:*:*:*:*"
    assert N.match_evidence([other], [HOST_OPENSSL]) == "name_only"


def test_no_cpe_data_is_name_only():
    assert N.match_evidence([], [HOST_OPENSSL]) == "name_only"
    assert N.match_evidence([CVE_OPENSSL], []) == "name_only"


def test_wildcard_products_never_match():
    star = "cpe:2.3:a:openssl:*:*:*:*:*:*:*:*:*"
    assert N.match_evidence([star], [star.replace("openssl:*", "openssl:openssl")]) == "name_only"


def test_garbage_does_not_crash():
    assert N.match_evidence(["", "x", "cpe:"], ["cpe:2.3"]) == "name_only"


class FakeConn:
    def __init__(self, rows): self.rows, self.executed = rows, []
    async def fetch(self, *a): return self.rows
    async def execute(self, sql, *args): self.executed.append(args)


class FakeDB:
    def __init__(self, rows): self.c = FakeConn(rows)
    def conn(self):
        c = self.c
        class Ctx:
            async def __aenter__(self_): return c
            async def __aexit__(self_, *e): return False
        return Ctx()


def _run(cve_cpes, asset_cpes, monkeypatch, name_only_state="unconfirmed"):
    fake = FakeDB([{"asset_id": "login01", "packages": ["deb:openssl"], "cpe_uris": asset_cpes}])
    monkeypatch.setattr(N, "db", fake)
    monkeypatch.setattr(N, "NAME_ONLY_STATE", name_only_state)
    v = SimpleNamespace(cve_id="CVE-2026-1", cpe_uris=cve_cpes, affected_packages=["product:openssl"])
    assert asyncio.run(N.match_assets(v)) == ["login01"]
    return fake.c.executed[0]


def test_name_only_match_is_stored_but_unconfirmed(monkeypatch):
    args = _run([], [HOST_OPENSSL], monkeypatch)
    assert args[3] == "name_only" and args[4] == "unconfirmed"


def test_cpe_match_is_open(monkeypatch):
    args = _run([CVE_OPENSSL], [HOST_OPENSSL], monkeypatch)
    assert args[3] == "cpe_product" and args[4] == "open"


def test_switch_restores_old_behaviour(monkeypatch):
    assert _run([], [HOST_OPENSSL], monkeypatch, name_only_state="open")[4] == "open"
