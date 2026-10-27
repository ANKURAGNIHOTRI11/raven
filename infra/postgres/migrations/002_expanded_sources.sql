-- Adds OTX threat intel + an expanded vendor/research/media RSS list, and
-- registers a bookkeeping row for the Telegram watcher (event-driven, not
-- polled by the generic crawler loop - see services/telegram_watcher).
--
-- The main postgres init scripts (infra/postgres/init/*.sql) only run once,
-- against an empty data volume. On an already-running instance, apply this
-- by hand:
--
--   docker compose exec -T postgres psql -U raven raven < infra/postgres/migrations/002_expanded_sources.sql
--
-- Trust scores: authoritative vendor PSIRTs sit near the existing NVD/KEV
-- tier; independent research blogs sit with GHSA/OSV; general news and
-- community/chat sources sit at or below the existing BleepingComputer/
-- SecurityWeek tier (0.45), since those are unverified narrative sources
-- whose value is early signal, not authority. Verify each URL before
-- relying on it in production - RSS locations drift over time and a dead
-- feed just opens its own circuit breaker rather than blocking anything.

INSERT INTO sources (source_id, name, url, source_class, parser, trust, poll_seconds) VALUES
 -- community threat intel
 ('otx',            'AlienVault OTX',              'https://otx.alienvault.com/api/v1/pulses/activity',        'community',     'otx', 0.35, 3600),

 -- vendor / research PSIRTs and security-research blogs (authoritative-ish)
 ('msrc_blog',      'Microsoft MSRC Blog',         'https://msrc.microsoft.com/blog/feed',                     'authoritative', 'rss', 0.85, 7200),
 ('projectzero',    'Google Project Zero',         'https://googleprojectzero.blogspot.com/feeds/posts/default','authoritative', 'rss', 0.88, 7200),
 ('googlesec',      'Google Security Blog',        'https://security.googleblog.com/feeds/posts/default',      'authoritative', 'rss', 0.85, 7200),
 ('zdi',            'Zero Day Initiative',         'https://www.zerodayinitiative.com/rss/published/',          'authoritative', 'rss', 0.85, 7200),
 ('talos',          'Cisco Talos',                 'https://blog.talosintelligence.com/feeds/posts/default',    'authoritative', 'rss', 0.82, 7200),
 ('mozilla_sec',    'Mozilla Security Blog',       'https://blog.mozilla.org/security/feed/',                   'authoritative', 'rss', 0.80, 14400),
 ('unit42',         'Palo Alto Unit42',            'https://unit42.paloaltonetworks.com/feed/',                 'authoritative', 'rss', 0.78, 14400),
 ('mandiant',       'Mandiant (Google Cloud)',     'https://cloud.google.com/blog/topics/threat-intelligence/rss','authoritative','rss', 0.80, 14400),
 ('sans_isc',       'SANS Internet Storm Center',  'https://isc.sans.edu/rssfeed_full.xml',                     'authoritative', 'rss', 0.80, 3600),
 ('cisa_advisories','CISA Cybersecurity Advisories','https://www.cisa.gov/cybersecurity-advisories/all.xml',    'authoritative', 'rss', 0.95, 3600),
 ('cisa_ics',       'CISA ICS Advisories',         'https://www.cisa.gov/uscert/ics/advisories/advisories.xml', 'authoritative', 'rss', 0.95, 7200),
 ('ncsc_uk',        'NCSC UK',                     'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml','authoritative', 'rss', 0.85, 14400),
 ('rapid7',         'Rapid7 Blog',                 'https://www.rapid7.com/blog/rss/',                          'authoritative', 'rss', 0.72, 14400),
 ('tenable',        'Tenable Blog',                'https://www.tenable.com/blog/feed',                          'authoritative', 'rss', 0.72, 14400),
 ('qualys',         'Qualys Blog',                 'https://blog.qualys.com/feed',                               'authoritative', 'rss', 0.72, 14400),
 ('checkpoint',     'Check Point Research',        'https://research.checkpoint.com/feed/',                     'authoritative', 'rss', 0.75, 14400),
 ('sentinelone',    'SentinelOne Labs',            'https://www.sentinelone.com/labs/feed/',                     'authoritative', 'rss', 0.72, 14400),
 ('securelist',     'Kaspersky Securelist',        'https://securelist.com/feed/',                               'authoritative', 'rss', 0.72, 14400),
 ('f5labs',         'F5 Labs',                     'https://www.f5.com/labs/rss-feeds/all.xml',                  'authoritative', 'rss', 0.70, 14400),
 ('portswigger',    'PortSwigger Research',        'https://portswigger.net/research/rss',                       'authoritative', 'rss', 0.75, 14400),

 -- general infosec media/news (same tier as the existing bleeping/secweek rows)
 ('krebs',          'Krebs on Security',           'https://krebsonsecurity.com/feed/',                          'media', 'rss', 0.50, 7200),
 ('thehackernews',  'The Hacker News',              'https://feeds.feedburner.com/TheHackersNews',                'media', 'rss', 0.45, 3600),
 ('darkreading',    'Dark Reading',                 'https://www.darkreading.com/rss.xml',                        'media', 'rss', 0.45, 7200),
 ('securityaffairs','Security Affairs',            'https://securityaffairs.com/feed',                            'media', 'rss', 0.42, 7200),
 ('schneier',       'Schneier on Security',         'https://www.schneier.com/feed/atom/',                        'media', 'rss', 0.55, 14400),
 ('sophos_news',    'Sophos News',                  'https://news.sophos.com/en-us/feed/',                        'media', 'rss', 0.48, 14400),
 ('malwarebytes',   'Malwarebytes Labs',            'https://www.malwarebytes.com/blog/feed/index.xml',           'media', 'rss', 0.45, 14400),
 ('packetstorm',    'Packet Storm',                 'https://packetstormsecurity.com/rss.xml',                    'media', 'rss', 0.40, 7200),
 ('exploitdb',      'Exploit-DB',                   'https://www.exploit-db.com/rss.xml',                         'media', 'rss', 0.45, 7200),
 ('trendmicro',     'Trend Micro Research',         'https://www.trendmicro.com/en_us/research.rss',              'media', 'rss', 0.55, 14400),

 -- event-driven, not polled by the generic loop (see services/telegram_watcher);
 -- this row exists purely so it participates in trust bookkeeping and shows
 -- up in the console like every other source
 ('telegram',       'Telegram channel watch',       'telegram://configured-channels',                             'media', 'telegram', 0.25, 86400)
ON CONFLICT (source_id) DO NOTHING;
