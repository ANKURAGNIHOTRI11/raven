import pytest

from parsers import NotAFeed, parse_rss

ITEM = "<item><title>t</title><description>d</description></item>"


def test_html_page_served_as_a_feed_is_a_failure_not_an_empty_success():
    """What mandiant, msrc_blog and packetstorm actually returned: HTML with HTTP 200."""
    page = b"<!doctype html><html lang='en'><head><base href='https://x.test/'></head><body>hi</body></html>"
    with pytest.raises(NotAFeed):
        parse_rss(page)


def test_well_formed_html_without_a_feed_root_is_rejected_too():
    with pytest.raises(NotAFeed) as err:
        parse_rss(b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body/></html>")
    assert "html" in str(err.value)


def test_error_message_is_short_and_carries_a_readable_excerpt():
    with pytest.raises(NotAFeed) as err:
        parse_rss(b"<!doctype html>" + b"x" * 5000)
    assert len(str(err.value)) < 250


def test_empty_but_valid_rss_feed_is_not_an_error():
    assert parse_rss(b"<rss version='2.0'><channel><title>quiet week</title></channel></rss>") == []


def test_empty_but_valid_atom_feed_is_not_an_error():
    assert parse_rss(b"<feed xmlns='http://www.w3.org/2005/Atom'><title>new blog</title></feed>") == []


def test_rss_1_0_rdf_root_is_accepted():
    rdf = (b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' xmlns='http://purl.org/rss/1.0/'>"
           b"<item><title>CVE-2025-77777 disclosed</title><description>d</description></item></rdf:RDF>")
    assert [r["cve_id"] for r in parse_rss(rdf)] == ["CVE-2025-77777"]


def test_feed_with_items_but_no_cves_still_returns_empty_list():
    assert parse_rss(f"<rss><channel>{ITEM}</channel></rss>".encode()) == []

def test_xml10_forbidden_control_bytes_in_article_text_are_sanitized():
    feed = (
        b"<rss><channel><item><title>Security advisory</title>"
        b"<description>Quoted terminal output:\x0bCVE-2026-12345</description>"
        b"</item></channel></rss>"
    )
    records = parse_rss(feed)
    assert [r["cve_id"] for r in records] == ["CVE-2026-12345"]
    assert "\x0b" not in records[0]["description"]

