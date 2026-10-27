-- RAVEN system of record.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ---------------------------------------------------------------- sources
CREATE TABLE IF NOT EXISTS sources (
    source_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    source_class    TEXT NOT NULL CHECK (source_class IN ('authoritative','community','media','internal')),
    parser          TEXT NOT NULL DEFAULT 'json',
    trust           REAL NOT NULL DEFAULT 0.5 CHECK (trust BETWEEN 0 AND 1),
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    poll_seconds    INTEGER NOT NULL DEFAULT 3600,
    last_success    TIMESTAMPTZ,
    last_error      TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    circuit_open_until   TIMESTAMPTZ,
    -- rolling reputation, adjusted by the feedback engine
    accepted_records BIGINT NOT NULL DEFAULT 0,
    quarantined_records BIGINT NOT NULL DEFAULT 0
);

-- --------------------------------------------------------------- raw zone
CREATE TABLE IF NOT EXISTS raw_documents (
    doc_id          TEXT PRIMARY KEY,
    source_id       TEXT NOT NULL REFERENCES sources(source_id),
    url             TEXT NOT NULL,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    content_sha256  TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    object_key      TEXT NOT NULL,
    UNIQUE (source_id, content_sha256)
);

CREATE TABLE IF NOT EXISTS quarantine (
    id              BIGSERIAL PRIMARY KEY,
    doc_id          TEXT,
    source_id       TEXT,
    reason          TEXT NOT NULL,
    detail          TEXT,
    severity        TEXT NOT NULL DEFAULT 'reject',
    raw_excerpt     TEXT,
    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed        BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS quarantine_src_idx ON quarantine(source_id, quarantined_at DESC);

-- --------------------------------------------------------- vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id          TEXT PRIMARY KEY,
    title           TEXT,
    description     TEXT,
    published       TIMESTAMPTZ,
    modified        TIMESTAMPTZ,
    cvss_vector     TEXT,
    cvss_base       REAL NOT NULL DEFAULT 0,
    cvss_version    TEXT DEFAULT '3.1',
    severity        TEXT NOT NULL DEFAULT 'none',
    cwe_ids         TEXT[] NOT NULL DEFAULT '{}',
    capec_ids       TEXT[] NOT NULL DEFAULT '{}',
    attack_techniques TEXT[] NOT NULL DEFAULT '{}',
    cpe_uris        TEXT[] NOT NULL DEFAULT '{}',
    affected_packages TEXT[] NOT NULL DEFAULT '{}',
    epss_score      REAL NOT NULL DEFAULT 0,
    epss_percentile REAL NOT NULL DEFAULT 0,
    kev             BOOLEAN NOT NULL DEFAULT FALSE,
    kev_due_date    TIMESTAMPTZ,
    exploit_maturity TEXT NOT NULL DEFAULT 'none',
    references_json JSONB NOT NULL DEFAULT '[]',
    provenance      TEXT[] NOT NULL DEFAULT '{}',
    source_trust    REAL NOT NULL DEFAULT 0.5,
    ingest_confidence REAL NOT NULL DEFAULT 1.0,
    normalized_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS vuln_kev_idx ON vulnerabilities(kev) WHERE kev;
CREATE INDEX IF NOT EXISTS vuln_epss_idx ON vulnerabilities(epss_percentile DESC);
CREATE INDEX IF NOT EXISTS vuln_cpe_idx ON vulnerabilities USING GIN (cpe_uris);
CREATE INDEX IF NOT EXISTS vuln_pkg_idx ON vulnerabilities USING GIN (affected_packages);
CREATE INDEX IF NOT EXISTS vuln_desc_trgm ON vulnerabilities USING GIN (description gin_trgm_ops);

-- ----------------------------------------------------------------- assets
CREATE TABLE IF NOT EXISTS assets (
    asset_id        TEXT PRIMARY KEY,
    hostname        TEXT,
    kind            TEXT NOT NULL DEFAULT 'host',
    environment     TEXT NOT NULL DEFAULT 'prod',
    criticality     SMALLINT NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
    internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    owner           TEXT,
    zone            TEXT DEFAULT 'default',
    cpe_uris        TEXT[] NOT NULL DEFAULT '{}',
    packages        TEXT[] NOT NULL DEFAULT '{}',
    compensating_controls TEXT[] NOT NULL DEFAULT '{}',
    connects_to     TEXT[] NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS asset_pkg_idx ON assets USING GIN (packages);
CREATE INDEX IF NOT EXISTS asset_cpe_idx ON assets USING GIN (cpe_uris);

CREATE TABLE IF NOT EXISTS findings (
    finding_id      TEXT PRIMARY KEY,
    cve_id          TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    match_reason    TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    state           TEXT NOT NULL DEFAULT 'open',
    UNIQUE (cve_id, asset_id)
);

-- ------------------------------------------------------------ graph + risk
CREATE TABLE IF NOT EXISTS graph_signals (
    cve_id          TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    blast_radius    INTEGER NOT NULL DEFAULT 0,
    reachability    REAL NOT NULL DEFAULT 0,
    chain_score     REAL NOT NULL DEFAULT 0,
    centrality      REAL NOT NULL DEFAULT 0,
    paths_json      JSONB NOT NULL DEFAULT '[]',
    model_version   TEXT NOT NULL DEFAULT 'gnn-0',
    adversarial_flag BOOLEAN NOT NULL DEFAULT FALSE,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, asset_id)
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id   TEXT PRIMARY KEY,
    cve_id          TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    fused_score     REAL NOT NULL,
    band            TEXT NOT NULL,
    confidence      REAL NOT NULL,
    ci_low          REAL NOT NULL,
    ci_high         REAL NOT NULL,
    components      JSONB NOT NULL DEFAULT '{}',
    evidence        JSONB NOT NULL DEFAULT '[]',
    graph_signal    JSONB,
    sla_hours       INTEGER NOT NULL DEFAULT 720,
    scorer_version  TEXT NOT NULL,
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS risk_score_idx ON risk_assessments(fused_score DESC, scored_at DESC);
CREATE INDEX IF NOT EXISTS risk_pair_idx ON risk_assessments(cve_id, asset_id, scored_at DESC);

-- --------------------------------------------------------------- decisions
CREATE TABLE IF NOT EXISTS agent_decisions (
    decision_id     TEXT PRIMARY KEY,
    assessment_id   TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('abstain','analyze','act')),
    confidence      REAL NOT NULL,
    rationale       TEXT,
    verifier_verdict TEXT NOT NULL DEFAULT 'unchecked',
    verifier_notes  TEXT,
    grounded        BOOLEAN NOT NULL DEFAULT FALSE,
    citations       TEXT[] NOT NULL DEFAULT '{}',
    plan            JSONB,
    blast_radius    INTEGER NOT NULL DEFAULT 0,
    auto_approved   BOOLEAN NOT NULL DEFAULT FALSE,
    guard_events    TEXT[] NOT NULL DEFAULT '{}',
    model_versions  JSONB NOT NULL DEFAULT '{}',
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS decision_action_idx ON agent_decisions(action, decided_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    decision_id     TEXT NOT NULL REFERENCES agent_decisions(decision_id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','approved','rejected','applied','rolled_back')),
    approver        TEXT,
    reason          TEXT,
    rollback_plan   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS approval_state_idx ON approvals(state, created_at);

-- --------------------------------------------------------------- feedback
CREATE TABLE IF NOT EXISTS feedback_events (
    event_id        TEXT PRIMARY KEY,
    decision_id     TEXT,
    cve_id          TEXT,
    asset_id        TEXT,
    kind            TEXT NOT NULL,
    model_name      TEXT,
    model_version   TEXT,
    predicted       REAL,
    observed        REAL,
    note            TEXT,
    analyst         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS model_trust (
    model_name      TEXT NOT NULL,
    model_version   TEXT NOT NULL,
    samples         INTEGER NOT NULL DEFAULT 0,
    brier           REAL,
    override_rate   REAL,
    trust_score     REAL NOT NULL DEFAULT 0.5,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (model_name, model_version)
);

CREATE TABLE IF NOT EXISTS training_examples (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          TEXT,
    asset_id        TEXT,
    features        JSONB NOT NULL,
    label           REAL NOT NULL,
    label_source    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    actor           TEXT NOT NULL,
    action          TEXT NOT NULL,
    subject         TEXT,
    detail          JSONB NOT NULL DEFAULT '{}',
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------- source seed
INSERT INTO sources (source_id, name, url, source_class, parser, trust, poll_seconds) VALUES
 ('nvd',        'NVD CVE API 2.0',      'https://services.nvd.nist.gov/rest/json/cves/2.0', 'authoritative', 'nvd',   0.98, 3600),
 ('cisa_kev',   'CISA Known Exploited', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 'authoritative', 'kev', 1.00, 21600),
 ('epss',       'FIRST EPSS v4',        'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', 'authoritative', 'epss', 0.95, 86400),
 ('osv',        'OSV.dev',              'https://api.osv.dev/v1/query',                     'community',     'osv',   0.85, 7200),
 ('ghsa',       'GitHub Advisories',    'https://api.github.com/advisories',                'community',     'ghsa',  0.88, 7200),
 ('redhat',     'Red Hat Security Data','https://access.redhat.com/hydra/rest/securitydata/cve.json', 'authoritative', 'redhat', 0.93, 7200),
 ('msrc',       'Microsoft MSRC',       'https://api.msrc.microsoft.com/cvrf/v3.0/updates', 'authoritative', 'msrc',  0.93, 21600),
 ('cisco',      'Cisco PSIRT openVuln', 'https://api.cisco.com/security/advisories/all',    'authoritative', 'rss',   0.90, 21600),
 ('fortinet',   'Fortinet PSIRT',       'https://filestore.fortinet.com/fortiguard/rss/ir.xml', 'authoritative', 'rss', 0.90, 21600),
 ('bleeping',   'BleepingComputer',     'https://www.bleepingcomputer.com/feed/',           'media',         'rss',   0.45, 3600),
 ('secweek',    'SecurityWeek',         'https://www.securityweek.com/feed/',               'media',         'rss',   0.45, 3600),
 ('cmdb',       'Internal CMDB/SBOM',   'file:///seed/assets.json',                         'internal',      'cmdb',  1.00, 900)
ON CONFLICT (source_id) DO NOTHING;


-- Expanded sources (OTX, vendor/research RSS, Telegram bookkeeping row) -
-- see infra/postgres/migrations/002_expanded_sources.sql for the same
-- content with rationale; kept in sync so a fresh install gets both in one
-- pass, while an existing deployment applies the migration file by hand.
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
