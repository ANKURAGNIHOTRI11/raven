# EPIC-01 public-source CVE metadata cross-check

## Purpose

A vendor reference that requires an account or sign-in must not stop CVE metadata
recovery. RAVEN records the inaccessible vendor reference and continues looking up
the same exact CVE identifier through independent, publicly accessible sources.

This increment expands the existing metadata worker. It does not change its field
write scope or make a search-engine summary an authoritative source.

## Public source adapters

The worker queries these sources independently for each CVE:

1. NVD CVE API — descriptions, publication/modification dates and references.
2. GitHub Security Advisories — exact CVE match, summary, description, NVD publication date and references.
3. OSV — exact identifier or alias match, details, dates and references.
4. CIRCL Vulnerability-Lookup — public multi-source record lookup; accepts CVE Record Format 5.x and OSV-shaped records.
5. CVE.org CVE Services — public GET of the CVE Record Format 5.x record by exact CVE ID.

Public API references:
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub Global Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [OSV API](https://google.github.io/osv.dev/api/)
- [CIRCL Vulnerability-Lookup API](https://vulnerability.circl.lu/api/)
- [CVE Services API](https://cveawg.mitre.org/api-docs/)

An optional Brave Web Search adapter is enabled only when
`RAVEN_BRAVE_SEARCH_API_KEY` is configured. It stores result URLs, titles and
short snippets as `unverified_search_leads` for discovery/review only. These
snippets never populate title, description, dates or references and do not count
as authoritative source evidence. Brave requires an API subscription token
([API docs](https://api-dashboard.search.brave.com/api-reference/web/search/get)).

A response is accepted only after validating its structure and exact CVE identifier
(or exact OSV alias). A 404 is a completed negative lookup. A 401/403 is logged as
`source_access_restricted`; other sources continue independently. A failed or
malformed source makes the overall lookup incomplete so that a no-match is not
recorded as definitive.

RAVEN spaces sequential CIRCL lookups by 3.1 seconds by default, or 1.6 seconds
when `RAVEN_CIRCL_API_KEY` is configured. These are conservative client-side
defaults, not a guarantee of the remote service's current quota. Operators should
check the live instance policy and tune `RAVEN_CIRCL_REQUEST_DELAY_SECONDS`
accordingly.

## Evidence and conflict handling

For each recovered field, the worker records source name, source URL, a SHA-256
value fingerprint and a bounded preview in `field_evidence`. It also stores
per-source completion/access status in `source_status`; optional Brave discovery
leads are labeled unverified. This metadata is written to the existing
`vulnerability_enrichment_audit` table only in explicit apply mode. The worker
adds the `field_evidence JSONB` and `source_status JSONB` columns idempotently
when the apply schema is prepared.

If independent sources disagree on title, description, publication date or
modification date, that field is marked as conflicting and is not automatically
written. Other non-conflicting missing fields remain independently eligible.
References are deduplicated and combined from matching source records.

The source priority for the initial selected value is NVD, GitHub Security
Advisories, OSV, CIRCL, then CVE.org. Priority is used only to make a stable
preview: a disagreement still blocks automatic writes for that field.

## Deliberate scope limits

This increment still updates only missing descriptive metadata:
`title`, `description`, `published`, `modified`, and `references_json`.
Existing values win. It does not automatically update CVSS, CWE, CPE, affected
versions, exploit maturity, KEV/EPSS, mitigations, patches, asset matches, graph,
risk, model or approval state. Those need separate typed schemas, field-specific
validation rules, source precedence and review gates.

Search-engine snippets and AI-generated overviews may be used by a future discovery
adapter to find candidate URLs, but must never be treated as source evidence or
written directly into vulnerability records. Retrieved pages and reference links
are untrusted input; only validated structured records are eligible for this worker.

## Operator validation

1. Run the existing worker in dry-run mode.
2. Run the read-only review preview and inspect the value plus field evidence for
   each CVE.
3. Resolve conflicts and confirm exact CVE identity.
4. Only then consider a separately approved, bounded apply.
5. Verify row values, audit evidence, and unchanged out-of-scope tables afterward.

No timer or unattended apply is installed by this feature.
