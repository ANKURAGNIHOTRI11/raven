from parsers import parse_rss


# ---- RSS full-text handling (found via talos returning 0 records) ----------

TALOS_STYLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><title>Blog</title>
<item><title><![CDATA[Microsoft, Adobe, Apple, and Foxit vulnerabilities]]></title>
<description><![CDATA[<p>Talos recently disclosed vulnerabilities in Adobe, Apple, Foxit Reader, and Microsoft.</p>]]></description>
<link>https://blog.example.test/roundup/</link>
<content:encoded><![CDATA[<p>Teaser.</p><h3>Photoshop</h3><p>TALOS-2026-2360 (CVE-2026-48388) is a privilege
escalation flaw in the installer.</p><h3>Foxit</h3><p>TALOS-2026-2420 (CVE-2026-57256) is a code execution flaw.</p>]]></content:encoded>
</item></channel></rss>"""


def test_rss_finds_cves_that_appear_only_in_the_full_text():
    ids = sorted(r["cve_id"] for r in parse_rss(TALOS_STYLE))
    assert ids == ["CVE-2026-48388", "CVE-2026-57256"]


def test_rss_atom_content_is_searched_and_link_href_is_used():
    atom = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
    <entry><title>Weekly notes</title><link rel="alternate" href="https://blog.example.test/p/1"/>
    <content type="html">&lt;p&gt;Fixed CVE-2025-11111 in the parser.&lt;/p&gt;</content></entry></feed>"""
    out = parse_rss(atom)
    assert [r["cve_id"] for r in out] == ["CVE-2025-11111"]
    assert out[0]["references"][0]["url"] == "https://blog.example.test/p/1"


def test_rss_xhtml_content_with_child_elements_is_searched():
    atom = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
    <entry><title>Post</title><content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">
    <p>See <b>CVE-2025-22222</b> for details.</p></div></content></entry></feed>"""
    assert [r["cve_id"] for r in parse_rss(atom)] == ["CVE-2025-22222"]


def test_rss_exploit_maturity_is_judged_near_the_mention_not_across_the_article():
    filler = " unrelated words" * 40
    body = ("The attacker exploited CVE-2025-33333 in the wild last week." + filler +
            " Separately, CVE-2025-44444 was patched quietly." )
    rss = ("<rss><channel><item><title>t</title><description>d</description>"
           f"<content:encoded xmlns:content='x'>{body}</content:encoded></item></channel></rss>").encode()
    got = {r["cve_id"]: r["exploit_maturity"] for r in parse_rss(rss)}
    assert got == {"CVE-2025-33333": "poc", "CVE-2025-44444": "none"}


def test_rss_description_stays_small_and_a_single_item_cannot_flood():
    ids = " ".join(f"CVE-2025-{n:05d}" for n in range(10000, 10400))
    rss = ("<rss><channel><item><title>big</title><description>teaser</description>"
           f"<content:encoded xmlns:content='x'>{ids}</content:encoded></item></channel></rss>").encode()
    out = parse_rss(rss)
    assert len(out) == 100                       # capped per item
    assert all(len(r["description"]) <= 2000 for r in out)


def test_rss_title_and_description_matches_still_work():
    rss = b"<rss><channel><item><title>CVE-2025-55555 exploited</title><description>x</description></item></channel></rss>"
    out = parse_rss(rss)
    assert out[0]["cve_id"] == "CVE-2025-55555" and out[0]["exploit_maturity"] == "poc"
