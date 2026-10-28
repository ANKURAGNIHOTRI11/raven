# EPIC-01: CVE metadata enrichment (isolated rollout)

## Scope

The optional `enrichment-worker` fills missing descriptive metadata from NVD, GitHub Security Advisories (GHSA), and OSV. It is not a replacement for the existing crawler/normalizer and does not emit bus events.

Eligible fields: `title`, `description`, `published`, `modified`, and `references_json`, and only when the existing field is empty or missing. A title equal to the CVE identifier is considered missing. The worker does **not** modify CVSS/EPSS/KEV, CPEs, package matches, exploit maturity, asset findings, graph signals, risk assessments, model state, agent decisions, remediation plans, or approval records.

## Safety defaults

- The Compose service uses the `enrichment` profile and is not started by normal `docker compose up -d`.
- The worker defaults to dry-run; it writes only when `--apply` is passed.
- Batch size defaults to 25 and is limited to 500.
- Each candidate is logged with source names and fields proposed; no descriptions or secrets are logged.
- Source requests are independent, bounded by timeouts, and tolerate one source being unavailable.
- Writes use conditional SQL so populated fields are retained.
- An audit table records applied source names, fields and references. It is created only with `--apply`.
- It does not reprocess the ingestion bus, rebuild indexes, retrain models, or invoke graph/risk services.

## Operator workflow

1. Build only the optional worker image: `docker compose build enrichment-worker`.
2. Preview a small batch (read-only): `docker compose run --rm --no-deps enrichment-worker --limit 10`.
3. Review the proposed field counts and sample candidates in logs.
4. Apply only after approval: `docker compose run --rm --no-deps enrichment-worker --limit 10 --apply`.
5. Repeat with bounded batches after verifying results. The worker is deliberately not scheduled automatically.

The runtime must provide `RAVEN_PG_DSN` and normal PostgreSQL credentials through the existing environment file. If the DSN is absent, the worker exits without connecting.

## Validation and acceptance

- Unit tests cover exact identifier matching, NVD English description parsing, GHSA/OSV matching, and safe reference URL handling.
- First rollout should use dry-run mode on 10 CVEs.
- After apply, validate counts for title/description/reference recovery and confirm graph/risk/approval tables have unchanged row counts.
- This is not a declaration of production readiness; rate limits, source coverage, field correctness, and audit review remain go-live gates.
