#!/usr/bin/env python3
"""
import_sources.py - validate ~150 candidate feeds and add the working ones to
RAVEN's `sources` table.

Run inside the crawler container (it has httpx, asyncpg, parsers, RAVEN_PG_DSN):

    docker compose cp import_sources.py crawler:/tmp/import_sources.py
    docker compose exec -T crawler python /tmp/import_sources.py            # dry run
    docker compose exec -T crawler python /tmp/import_sources.py --apply    # insert

Or without copying anything:

    docker compose exec -T crawler python - < import_sources.py             # dry run
    docker compose exec -T crawler python - --apply < import_sources.py     # insert

What it does
  1. Dedupes the candidate list by URL and skips URLs already in `sources`.
  2. Fetches each one (TLS verification always ON) and keeps only real feeds:
     HTTP 200, parses as XML, contains at least one item/entry.
  3. Reads the `sources` columns from information_schema, clones an existing
     row (default: schneier) as a template and overrides source_id / url / name.
     Nullable "state" columns (last_*, etag, ...) are reset to NULL.
  4. Writes a report to /tmp/feed_report.tsv (every candidate, with its verdict).
Nothing is written to the database unless --apply is given.
"""
import argparse
import asyncio
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

import httpx

# (name, url, category, priority)
CANDIDATES = [
    # Government / CERT
    ("CISA Alerts", "https://www.cisa.gov/uscert/ncas/alerts.xml", "ADVISORY", "CRITICAL"),
    ("CISA Bulletins", "https://www.cisa.gov/uscert/ncas/bulletins.xml", "ADVISORY", "HIGH"),
    ("CISA Current Activity", "https://www.cisa.gov/uscert/ncas/current-activity.xml", "ADVISORY", "HIGH"),
    ("US-CERT Tips", "https://www.cisa.gov/uscert/ncas/tips.xml", "ADVISORY", "MEDIUM"),
    ("SANS Internet Storm", "https://isc.sans.edu/rssfeed_full.xml", "ADVISORY", "HIGH"),
    ("SANS NewsBites", "https://www.sans.org/newsletters/newsbites/rss", "NEWS", "HIGH"),
    ("NCSC UK Advisories", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "ADVISORY", "HIGH"),
    ("NCSC UK News", "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml", "NEWS", "MEDIUM"),
    ("ENISA News", "https://www.enisa.europa.eu/news/enisa-news/rss_news", "ADVISORY", "MEDIUM"),
    ("AusCERT", "https://auscert.org.au/rss/bulletins/", "ADVISORY", "HIGH"),
    ("CERT/CC", "https://www.kb.cert.org/vuls/atomfeed", "ADVISORY", "HIGH"),
    ("JPCERT", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", "ADVISORY", "HIGH"),
    ("Canadian CCCS", "https://www.cyber.gc.ca/api/rss/alerts-advisories", "ADVISORY", "HIGH"),
    ("Singapore CSA", "https://www.csa.gov.sg/rss/advisories", "ADVISORY", "MEDIUM"),
    ("BSI Germany", "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_WarnID.xml", "ADVISORY", "HIGH"),
    # CVE databases
    ("VulDB Recent", "https://vuldb.com/?rss.recent", "CVE", "HIGH"),
    ("VulDB Critical", "https://vuldb.com/?rss.recent&cvss=critical", "CVE", "CRITICAL"),
    ("OpenCVE Critical", "https://www.opencve.io/cve?cvss=critical&format=rss", "CVE", "CRITICAL"),
    ("CVE Details", "https://www.cvedetails.com/vulnerability-feed.php?cvssscoremin=7&cvssscoremax=10&hasexp=0&opec=1&opov=1&opcsrf=1&opfileinc=1&opdirt=1&opmemc=1&ophttprs=1&opbyp=1&opxss=1&opsqli=1&orderby=3&rss=1&type=cves", "CVE", "HIGH"),
    ("Vulmon Recent", "https://vulmon.com/rss?q=recent", "CVE", "HIGH"),
    # Vendors
    ("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss", "VENDOR", "HIGH"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "VENDOR", "HIGH"),
    ("Azure Security Blog", "https://azure.microsoft.com/en-us/blog/topics/security/feed/", "CLOUD", "HIGH"),
    ("Red Hat Security Blog", "https://www.redhat.com/en/rss/blog/channel/security", "VENDOR", "HIGH"),
    ("Ubuntu Security", "https://ubuntu.com/security/notices/rss.xml", "VENDOR", "HIGH"),
    ("Debian Security", "https://www.debian.org/security/dsa-long", "VENDOR", "HIGH"),
    ("Fedora Security", "https://bodhi.fedoraproject.org/rss/updates/?type=security", "VENDOR", "MEDIUM"),
    ("Arch Linux Security", "https://security.archlinux.org/advisory/feed.atom", "VENDOR", "MEDIUM"),
    ("Alpine Linux Security", "https://secdb.alpinelinux.org/alpine.atom", "VENDOR", "MEDIUM"),
    ("SUSE Security", "https://www.suse.com/support/update/feed.rdf", "VENDOR", "HIGH"),
    ("openSUSE Security", "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/feed.rss2", "VENDOR", "MEDIUM"),
    ("Gentoo Security", "https://security.gentoo.org/glsa/feed.rss2", "VENDOR", "MEDIUM"),
    ("Apple Security Updates", "https://support.apple.com/en-us/rss/securityupdates.rss", "VENDOR", "HIGH"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default", "RESEARCH", "HIGH"),
    ("Google Security Blog", "https://security.googleblog.com/feeds/posts/default", "VENDOR", "HIGH"),
    ("Android Security", "https://source.android.com/docs/security/bulletin/feed.xml", "VENDOR", "HIGH"),
    ("Chrome Releases", "https://chromereleases.googleblog.com/feeds/posts/default", "VENDOR", "MEDIUM"),
    ("Mozilla Security Blog", "https://blog.mozilla.org/security/feed/", "VENDOR", "MEDIUM"),
    ("Mozilla Foundation Sec", "https://www.mozilla.org/en-US/security/advisories/feed/", "VENDOR", "HIGH"),
    ("Cisco Security Advisories", "https://tools.cisco.com/security/center/eventResponses.x?column=pubDate&ord=desc&format=xml", "VENDOR", "HIGH"),
    ("Cisco Talos Blog", "https://blog.talosintelligence.com/feeds/posts/default", "RESEARCH", "HIGH"),
    ("VMware Security", "https://www.vmware.com/security/advisories/rss.xml", "VENDOR", "HIGH"),
    ("Juniper Security", "https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES&rss=1", "VENDOR", "HIGH"),
    ("Fortinet PSIRT", "https://www.fortiguard.com/rss/ir.xml", "VENDOR", "HIGH"),
    ("Palo Alto Networks", "https://security.paloaltonetworks.com/rss.xml", "VENDOR", "HIGH"),
    ("F5 Security", "https://support.f5.com/csp/api/v1/contents?rss&ct=security%20advisory", "VENDOR", "HIGH"),
    ("SAP Security Notes", "https://dam.sap.com/mac/app/e/live/asset/;entryId=rss/rss.xml", "VENDOR", "HIGH"),
    ("Oracle Security Alerts", "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml", "VENDOR", "HIGH"),
    ("Adobe Security", "https://helpx.adobe.com/security/rss/security-bulletins.xml", "VENDOR", "HIGH"),
    ("Citrix Security", "https://support.citrix.com/feed/products/all/notifications/security", "VENDOR", "HIGH"),
    ("Atlassian Security", "https://confluence.atlassian.com/security/rss", "VENDOR", "HIGH"),
    ("GitLab Security", "https://about.gitlab.com/security/feed.xml", "VENDOR", "MEDIUM"),
    ("WordPress Security", "https://wordpress.org/news/category/security/feed/", "VENDOR", "HIGH"),
    ("Drupal Security", "https://www.drupal.org/security/rss.xml", "VENDOR", "HIGH"),
    ("Magento Security", "https://magento.com/security/patches/rss", "VENDOR", "HIGH"),
    ("Nginx Security", "https://nginx.org/en/security_advisories.xml", "VENDOR", "HIGH"),
    ("OpenSSL Security", "https://www.openssl.org/news/secadv_autotoc.xml", "VENDOR", "CRITICAL"),
    ("Apache Security", "https://httpd.apache.org/security/vulnerabilities_24.atom", "VENDOR", "HIGH"),
    ("Kubernetes Security", "https://kubernetes.io/feed.xml", "VENDOR", "HIGH"),
    ("Docker Security", "https://www.docker.com/blog/feed/", "VENDOR", "MEDIUM"),
    # Exploit DBs / disclosure lists
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "EXPLOIT", "CRITICAL"),
    ("Packet Storm", "https://packetstormsecurity.com/files/rss/files.xml", "EXPLOIT", "HIGH"),
    ("Packet Storm News", "https://packetstormsecurity.com/files/rss/news.xml", "NEWS", "MEDIUM"),
    ("Full Disclosure", "https://seclists.org/rss/fulldisclosure.rss", "DISCLOSURE", "HIGH"),
    ("Bugtraq", "https://seclists.org/rss/bugtraq.rss", "DISCLOSURE", "HIGH"),
    ("OSS Security", "https://seclists.org/rss/oss-sec.rss", "DISCLOSURE", "HIGH"),
    ("SecFocus Vulnerabilities", "https://www.securityfocus.com/rss/vulnerabilities.xml", "CVE", "HIGH"),
    ("SecFocus News", "https://www.securityfocus.com/rss/news.xml", "NEWS", "MEDIUM"),
    ("0day.today", "https://0day.today/rss", "EXPLOIT", "CRITICAL"),
    # Threat intel
    ("AlienVault OTX", "https://otx.alienvault.com/api/v1/pulses/subscribed?format=rss", "THREAT", "HIGH"),
    ("Recorded Future", "https://www.recordedfuture.com/feed", "THREAT", "HIGH"),
    ("Threatpost", "https://threatpost.com/feed/", "THREAT", "HIGH"),
    ("Malwarebytes Labs", "https://blog.malwarebytes.com/feed/", "THREAT", "HIGH"),
    ("Kaspersky SecureList", "https://securelist.com/feed/", "THREAT", "HIGH"),
    ("Sophos Naked Security", "https://nakedsecurity.sophos.com/feed/", "THREAT", "HIGH"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/feed/", "THREAT", "HIGH"),
    ("Symantec Threat Intel", "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/rss.xml", "THREAT", "HIGH"),
    ("Crowdstrike Blog", "https://www.crowdstrike.com/blog/feed/", "THREAT", "HIGH"),
    ("SentinelOne Blog", "https://www.sentinelone.com/blog/feed/", "THREAT", "HIGH"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/", "THREAT", "HIGH"),
    ("Mandiant Blog", "https://www.mandiant.com/resources/blog/rss.xml", "THREAT", "HIGH"),
    ("IBM X-Force", "https://www.ibm.com/blogs/x-force/feed/", "THREAT", "HIGH"),
    ("Proofpoint Blog", "https://www.proofpoint.com/us/blog/feed", "THREAT", "MEDIUM"),
    ("Check Point Research", "https://research.checkpoint.com/feed/", "THREAT", "HIGH"),
    ("Secureworks Blog", "https://www.secureworks.com/rss?feed=blog", "THREAT", "HIGH"),
    ("Trend Micro Research", "https://www.trendmicro.com/en_us/research.rss", "THREAT", "HIGH"),
    ("McAfee Advanced Threat", "https://www.trellix.com/en-us/about/newsroom/stories/research.rss", "THREAT", "HIGH"),
    ("Bitdefender Labs", "https://www.bitdefender.com/blog/labs/feed/", "THREAT", "HIGH"),
    ("Cybereason Blog", "https://www.cybereason.com/blog/rss.xml", "THREAT", "MEDIUM"),
    ("Huntress Labs", "https://www.huntress.com/blog/rss.xml", "THREAT", "HIGH"),
    ("Red Canary Blog", "https://redcanary.com/blog/feed/", "THREAT", "HIGH"),
    ("Dragos ICS", "https://www.dragos.com/blog/feed/", "THREAT", "HIGH"),
    ("Claroty Blog", "https://claroty.com/blog/feed", "THREAT", "MEDIUM"),
    # Research blogs
    ("Rapid7 Blog", "https://blog.rapid7.com/rss/", "RESEARCH", "HIGH"),
    ("Tenable Blog", "https://www.tenable.com/blog/feed", "RESEARCH", "HIGH"),
    ("Qualys Blog", "https://blog.qualys.com/feed", "RESEARCH", "HIGH"),
    ("PortSwigger Research", "https://portswigger.net/research/rss", "RESEARCH", "HIGH"),
    ("NCC Group Research", "https://research.nccgroup.com/feed/", "RESEARCH", "HIGH"),
    ("Bishop Fox Blog", "https://bishopfox.com/blog/rss", "RESEARCH", "HIGH"),
    ("Synacktiv Blog", "https://www.synacktiv.com/en/publications.rss", "RESEARCH", "HIGH"),
    ("Pentest Partners", "https://www.pentestpartners.com/security-blog/feed/", "RESEARCH", "MEDIUM"),
    ("Offensive Security Blog", "https://www.offensive-security.com/blog/rss/", "RESEARCH", "HIGH"),
    ("Vulncheck Blog", "https://vulncheck.com/blog/rss.xml", "RESEARCH", "HIGH"),
    ("Assetnote Research", "https://www.assetnote.io/resources/research/rss", "RESEARCH", "HIGH"),
    ("Wiz Blog", "https://www.wiz.io/blog/rss.xml", "RESEARCH", "HIGH"),
    ("Aqua Security Blog", "https://blog.aquasec.com/rss.xml", "RESEARCH", "HIGH"),
    ("Snyk Security", "https://snyk.io/blog/feed/", "RESEARCH", "MEDIUM"),
    ("Trail of Bits Blog", "https://blog.trailofbits.com/feed/", "RESEARCH", "HIGH"),
    ("Exodus Intelligence", "https://blog.exodusintel.com/feed/", "RESEARCH", "HIGH"),
    ("Zimperium Blog", "https://blog.zimperium.com/feed/", "RESEARCH", "MEDIUM"),
    ("Horizon3 Blog", "https://www.horizon3.ai/blog/rss.xml", "RESEARCH", "HIGH"),
    ("Watchtowr Labs", "https://labs.watchtowr.com/rss/", "RESEARCH", "HIGH"),
    ("Summoning Team", "https://www.summoningteam.blog/rss", "RESEARCH", "HIGH"),
    ("Praetorian Blog", "https://www.praetorian.com/blog/feed/", "RESEARCH", "MEDIUM"),
    ("Detectify Labs", "https://labs.detectify.com/feed/", "RESEARCH", "MEDIUM"),
    ("WithSecure Labs", "https://labs.withsecure.com/feed", "RESEARCH", "MEDIUM"),
    # News
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "NEWS", "HIGH"),
    ("Bleeping Computer", "https://www.bleepingcomputer.com/feed/", "NEWS", "HIGH"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "NEWS", "HIGH"),
    ("Dark Reading", "https://www.darkreading.com/rss_simple.asp", "NEWS", "HIGH"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek", "NEWS", "HIGH"),
    ("SC Magazine", "https://www.scmagazine.com/feed", "NEWS", "MEDIUM"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/", "NEWS", "MEDIUM"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", "NEWS", "MEDIUM"),
    ("Security Affairs", "https://securityaffairs.com/feed", "NEWS", "HIGH"),
    ("CyberScoop", "https://cyberscoop.com/feed/", "NEWS", "HIGH"),
    ("Risky Business", "https://risky.biz/feeds/risky-business/", "NEWS", "HIGH"),
    ("Cybersecurity Dive", "https://www.cybersecuritydive.com/feeds/news/", "NEWS", "MEDIUM"),
    ("Recorded Future News", "https://therecord.media/feed", "NEWS", "HIGH"),
    ("DataBreaches.net", "https://www.databreaches.net/feed/", "NEWS", "HIGH"),
    ("Graham Cluley", "https://grahamcluley.com/feed/", "NEWS", "MEDIUM"),
    ("Troy Hunt Blog", "https://www.troyhunt.com/rss/", "BLOG", "HIGH"),
    ("Threatintelligence.eu", "https://threatintelligence.eu/feed/", "THREAT", "MEDIUM"),
    ("Cybercrime Magazine", "https://cybersecurityventures.com/feed/", "NEWS", "LOW"),
    ("Bank Info Security", "https://www.bankinfosecurity.com/rss-feeds", "NEWS", "MEDIUM"),
    ("GovInfoSecurity", "https://www.govinfosecurity.com/rss-feeds", "NEWS", "MEDIUM"),
    # Cloud
    ("AWS Security Blog", "https://aws.amazon.com/blogs/security/feed/", "CLOUD", "HIGH"),
    ("GCP Security Blog", "https://cloud.google.com/blog/products/identity-security/rss/", "CLOUD", "HIGH"),
    ("Sysdig Blog", "https://sysdig.com/blog/feed/", "CLOUD", "MEDIUM"),
    ("Lacework Blog", "https://www.lacework.com/blog/feed/", "CLOUD", "MEDIUM"),
    ("Orca Security Blog", "https://orca.security/resources/blog/feed/", "CLOUD", "MEDIUM"),
    # Malware / ransomware
    ("MalwareBazaar", "https://bazaar.abuse.ch/export/rss/", "MALWARE", "HIGH"),
    ("URLhaus", "https://urlhaus.abuse.ch/feeds/rss/", "MALWARE", "HIGH"),
    ("Any.run Blog", "https://any.run/cybersecurity-blog/feed/", "MALWARE", "HIGH"),
    ("Hybrid Analysis Blog", "https://www.hybrid-analysis.com/blog/feed", "MALWARE", "HIGH"),
    ("Ransomware.live", "https://ransomware.live/feeds/posts.rss", "MALWARE", "CRITICAL"),
    ("ID Ransomware Blog", "https://id-ransomware.blogspot.com/feeds/posts/default", "MALWARE", "HIGH"),
    # Pentest / red team
    ("HackerOne Hacktivity", "https://hackerone.com/hacktivity.rss", "BUGBOUNTY", "HIGH"),
    ("SpecterOps Blog", "https://posts.specterops.io/feed", "RESEARCH", "HIGH"),
    ("TrustedSec Blog", "https://trustedsec.com/blog/rss", "RESEARCH", "HIGH"),
    ("NetSPI Blog", "https://www.netspi.com/blog/feed/", "RESEARCH", "MEDIUM"),
    ("Cobalt Strike Blog", "https://www.cobaltstrike.com/blog/feed/", "RESEARCH", "MEDIUM"),
    ("Sektor7 Blog", "https://blog.sektor7.net/#!rss", "RESEARCH", "MEDIUM"),
    # ICS / OT
    ("ICS-CERT Advisories", "https://www.cisa.gov/ics-advisories.xml", "ICS", "CRITICAL"),
    ("Applied Risk Blog", "https://applied-risk.com/blog?format=rss", "ICS", "MEDIUM"),
    ("OTORIO Blog", "https://www.otorio.com/blog/feed/", "ICS", "MEDIUM"),
    # OSINT
    ("DarkFeed", "https://darkfeed.io/feed/", "OSINT", "HIGH"),
    ("IntelligenceX Blog", "https://blog.intelx.io/feed/", "OSINT", "HIGH"),
    ("Shodan Blog", "https://blog.shodan.io/rss/", "OSINT", "HIGH"),
    ("Censys Blog", "https://censys.io/blog/feed/", "OSINT", "MEDIUM"),
]


# Likely current URLs for important sources whose old URLs in the original list are dead.
# They are validated like everything else, so wrong guesses are simply dropped.
CANDIDATES += [
    ("CISA Cybersecurity Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "ADVISORY", "CRITICAL"),
    ("CISA Alerts New", "https://www.cisa.gov/cybersecurity-advisories/alerts.xml", "ADVISORY", "CRITICAL"),
    ("CISA ICS Advisories New", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "ICS", "CRITICAL"),
    ("CISA ICS Medical Advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml", "ICS", "HIGH"),
    ("Cisco PSIRT Advisories", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "VENDOR", "HIGH"),
    ("Google Project Zero Alt", "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss", "RESEARCH", "HIGH"),
    ("Google Security Blog Alt", "https://security.googleblog.com/feeds/posts/default?alt=rss", "VENDOR", "HIGH"),
    ("Cisco Talos Alt", "https://blog.talosintelligence.com/rss/", "RESEARCH", "HIGH"),
    ("Mandiant Google Cloud", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "THREAT", "HIGH"),
    ("MSRC Blog Feed", "https://msrc.microsoft.com/blog/feed/", "VENDOR", "HIGH"),
    ("Zero Day Initiative Published", "https://www.zerodayinitiative.com/rss/published/", "ADVISORY", "HIGH"),
    ("Zero Day Initiative Upcoming", "https://www.zerodayinitiative.com/rss/upcoming/", "ADVISORY", "MEDIUM"),
]

# Per-category settings. Edit freely. trust is 0..1 (template row, Schneier, is 0.55).
TRUST = {"ADVISORY": 0.85, "VENDOR": 0.85, "ICS": 0.85, "CVE": 0.70, "CLOUD": 0.70,
         "RESEARCH": 0.65, "THREAT": 0.60, "NEWS": 0.55, "BLOG": 0.55, "MALWARE": 0.55,
         "DISCLOSURE": 0.50, "EXPLOIT": 0.50, "BUGBOUNTY": 0.50, "OSINT": 0.40}
POLL = {"CRITICAL": 3600, "HIGH": 7200, "MEDIUM": 14400, "LOW": 43200}
# source_class assignment. Classes must already exist in your table:
# authoritative / community / internal / media. Trust is taken from the median of
# the existing rows of that class, so it follows your own scale.
AUTHORITATIVE_CATS = {"ADVISORY", "ICS"}
AUTHORITATIVE_IDS = {  # vendor/project feeds that are the primary advisory channel
    "ubuntu_security", "debian_security", "fedora_security", "arch_linux_security",
    "gentoo_security", "drupal_security", "cisco_psirt_advisories", "microsoft_msrc",
    "palo_alto_networks", "fortinet_psirt", "oracle_security_alerts", "adobe_security",
    "citrix_security", "atlassian_security", "f5_security", "sap_security_notes",
    "juniper_security", "suse_security", "vmware_security", "openssl_security",
    "nginx_security", "apache_security", "android_security", "magento_security",
    "mozilla_foundation_sec", "chrome_releases", "alpine_linux_security",
    "opensuse_security", "cisco_security_advisories"}
COMMUNITY_CATS = {"CVE", "DISCLOSURE", "EXPLOIT", "OSINT", "BUGBOUNTY"}
# Existing community rows are structured feeds (median 0.85); free-text community feeds
# should sit at or below media (median 0.45), so they get explicit values.
COMMUNITY_TRUST = {"CVE": 0.60, "DISCLOSURE": 0.40, "EXPLOIT": 0.40, "OSINT": 0.35, "BUGBOUNTY": 0.40}


def class_of(cat: str, sid: str) -> str:
    if cat in AUTHORITATIVE_CATS or sid in AUTHORITATIVE_IDS:
        return "authoritative"
    if cat in COMMUNITY_CATS:
        return "community"
    return "media"


# Not importable as plain public RSS: needs an API key / has its own parser.
SKIP_URLS = {
    "https://vulmon.com/rss?q=recent",  # 1 item, no CVEs
    "https://otx.alienvault.com/api/v1/pulses/subscribed?format=rss",
}

UA = {"User-Agent": "RAVEN/1.0 (+security-intel)"}
REPORT = "/tmp/feed_report.tsv"
# columns that are runtime state; reset to NULL on the cloned row when nullable
STATE_COLS = {"etag", "last_modified", "last_fetched", "last_fetched_at", "last_success",
              "last_success_at", "last_error", "last_status", "last_run", "last_run_at",
              "last_seen", "last_checked", "last_checked_at", "fetched_at"}


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


async def check(client, sem, cand):
    name, url, cat, prio = cand
    async with sem:
        r, last = None, None
        for attempt in range(3):
            try:
                r = await client.get(url)
                break
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                last = exc
                await asyncio.sleep(2 * (attempt + 1))
            except Exception as exc:
                return ("FETCH_ERR", cand, f"{type(exc).__name__}: {str(exc)[:60]}")
        if r is None:
            return ("FETCH_ERR", cand, f"{type(last).__name__} after 3 tries: {str(last)[:50]}")
    if r.status_code != 200:
        return ("HTTP_ERR", cand, str(r.status_code))
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        return ("NOT_XML", cand, f"{r.headers.get('content-type', '')[:30]} final={r.url}")
    items = sum(1 for e in root.iter() if e.tag.split("}")[-1] in ("item", "entry"))
    if items == 0:
        return ("NO_ITEMS", cand, f"final={r.url}")
    cves = 0
    try:
        import parsers
        cves = len({x["cve_id"] for x in parsers.parse_rss(r.content)})
    except Exception:
        pass
    return ("OK", cand, f"items={items} cve_ids={cves}")


async def main(apply: bool, template_id: str, concurrency: int, allow_same_host: bool):
    import asyncpg

    conn = await asyncpg.connect(os.environ["RAVEN_PG_DSN"])
    cols = await conn.fetch(
        "SELECT column_name, data_type, is_nullable, column_default "
        "FROM information_schema.columns WHERE table_name='sources' ORDER BY ordinal_position")
    colnames = [c["column_name"] for c in cols]
    meta = {c["column_name"]: c for c in cols}
    print("sources columns:", colnames)

    existing = await conn.fetch("SELECT * FROM sources")
    have_ids = {r["source_id"] for r in existing}
    have_urls = {r["url"] for r in existing}
    template = next((r for r in existing if r["source_id"] == template_id), None)
    if template is None:
        template = next((r for r in existing if "http" in str(r["url"])), None)
    if template is None:
        sys.exit("no template row found in sources; pass --template <source_id>")
    print(f"template row: {template['source_id']}")
    print("template values:", {k: v for k, v in dict(template).items() if k != "url"})

    from urllib.parse import urlparse
    have_hosts = {urlparse(r["url"]).netloc.lower() for r in existing if r["parser"] == "rss"}
    import statistics
    classes = {r["source_class"] for r in existing}
    cls_trust = {c: round(statistics.median([r["trust"] for r in existing if r["source_class"] == c]), 3)
                 for c in classes}
    print("existing trust by class (median):", cls_trust)
    print("existing source_class values:", sorted(classes))
    seen, todo, same_host = set(), [], []
    for cand in CANDIDATES:
        url = cand[1]
        if url in seen or url in have_urls or url in SKIP_URLS:
            continue
        seen.add(url)
        if urlparse(url).netloc.lower() in have_hosts and not allow_same_host:
            same_host.append(cand)
            continue
        todo.append(cand)
    if same_host:
        print("skipped, host already covered by an existing source (use --allow-same-host to include):")
        for c in same_host:
            print(f"   {c[0]:32} {c[1]}")
    print(f"{len(CANDIDATES)} candidates -> {len(todo)} to check "
          f"(after dedupe / already present / skipped)")

    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=True, timeout=30, headers=UA) as client:
        results = await asyncio.gather(*[check(client, sem, c) for c in todo])

    with open(REPORT, "w") as fh:
        for verdict, (name, url, cat, prio), note in sorted(results, key=lambda r: (r[0] != "OK", r[0], r[1][0])):
            fh.write(f"{verdict}\t{name}\t{cat}\t{url}\t{note}\n")
    print("verdicts:", dict(Counter(r[0] for r in results)), f"(full report: {REPORT})")

    print("\nFAILED (CRITICAL/HIGH only; everything is in the report):")
    prio_of = {c[1]: c[3] for c in CANDIDATES}
    for verdict, (name, url, cat, prio), note in sorted(results, key=lambda r: r[1][0]):
        if verdict != "OK" and prio in ("CRITICAL", "HIGH"):
            print(f"   {verdict:9} {name:32} {note[:60]}")
    print()
    ok = [r for r in results if r[0] == "OK"]
    name_col = next((c for c in ("name", "display_name", "title") if c in meta), None)
    inserted = 0
    for _, (name, url, cat, prio), note in ok:
        sid = slug(name)
        base, n = sid, 2
        while sid in have_ids:
            sid, n = f"{base}_{n}", n + 1
        row = dict(template)
        row["source_id"] = sid
        row["url"] = url
        cls = class_of(cat, sid)
        if cls not in classes:
            cls = template["source_class"]
        row["source_class"] = cls
        row["trust"] = cls_trust.get(cls, TRUST.get(cat, 0.55))
        if cls == "community" and cat in COMMUNITY_TRUST:
            row["trust"] = COMMUNITY_TRUST[cat]
        row["poll_seconds"] = POLL.get(prio, 14400)
        row["accepted_records"] = 0
        row["quarantined_records"] = 0
        row["consecutive_failures"] = 0
        if name_col:
            row[name_col] = name
        for col in list(row):
            if col in STATE_COLS and meta[col]["is_nullable"] == "YES":
                row[col] = None
        have_ids.add(sid)
        print(f"  {'ADD' if apply else 'would add'}  {sid:32} {cat:10} class={row['source_class']:10} trust={row['trust']:.2f} poll={row['poll_seconds']:5} {note}")
        if apply:
            keys = list(row)
            placeholders = ", ".join(f"${i + 1}" for i in range(len(keys)))
            await conn.execute(
                f"INSERT INTO sources ({', '.join(keys)}) VALUES ({placeholders}) "
                f"ON CONFLICT DO NOTHING", *[row[k] for k in keys])
            inserted += 1
    await conn.close()
    if apply:
        print(f"inserted {inserted} sources")
    else:
        print(f"dry run: {len(ok)} sources would be added; re-run with --apply")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="insert into the database")
    ap.add_argument("--template", default="schneier", help="existing source_id to clone")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--allow-same-host", action="store_true",
                    help="include candidates whose host already has a source")
    args = ap.parse_args()
    asyncio.run(main(args.apply, args.template, args.concurrency, args.allow_same_host))
