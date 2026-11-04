# EPIC-01: CVE metadata enrichment (bare-metal rollout)

## Scope

The CPU-only enrichment worker fills missing descriptive metadata from NVD, GitHub Security Advisories (GHSA), and OSV. It complements the existing crawler/normalizer and does not emit bus events.

Eligible fields: `title`, `description`, `published`, `modified`, and `references_json`, and only when the existing field is empty or missing. A title equal to the CVE identifier is considered missing. The worker does **not** modify CVSS/EPSS/KEV, CPEs, package matches, exploit maturity, asset findings, graph signals, risk assessments, model state, agent decisions, remediation plans, or approval records.

## Execution model

- The enrichment worker runs directly on the host with Python and a virtual environment; it is not part of Docker Compose and does not require a GPU.
- `raven-enrichment-worker.service` is a one-shot dry-run unit with a default batch limit of 25.
- `raven-enrichment-apply@.service` is a separate one-shot template; starting `raven-enrichment-apply@10.service` explicitly passes `--apply` with a limit of 10.
- No systemd timer is installed or enabled. Runs are operator-initiated only.
- Unit files use the example deployment account `raven`, checkout `/opt/raven`, and environment file `/etc/raven/raven-enrichment.env`. Adjust those values to the actual host account and checkout before installing.

## Safety defaults

- Dry-run is the default; only the dedicated apply unit passes `--apply`.
- Batch size is limited to 1..500.
- Logs include CVE IDs, source names and proposed field flags, but not descriptions or secrets.
- Source requests are independent, bounded by timeouts, and tolerate one source being unavailable.
- Writes use conditional SQL so populated fields are retained.
- An audit table records applied source names, fields and references. It is created only with `--apply`; dry-run checks whether it exists and remains read-only on a fresh database.
- Every recorded apply attempt has a seven-day cooldown, including partial fills, to prevent repeatedly querying CVEs whose remaining metadata is unavailable from current sources.
- The worker does not reprocess the ingestion bus, rebuild indexes, retrain models, or invoke graph/risk services.

## Host installation

From the checked-out repository, create a dedicated virtual environment. These packages are the worker's direct runtime dependencies; the shared settings module is made available using `PYTHONPATH`.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install "asyncpg>=0.29" "httpx==0.27.2" "pydantic-settings>=2.2"
```

Create a root-readable environment file at `/etc/raven/raven-enrichment.env`. It must contain at least `RAVEN_PG_DSN`; add `RAVEN_NVD_API_KEY` and `RAVEN_GITHUB_TOKEN` when available. Do not commit this file or put secret values in the unit files.

Install the units after adjusting their `User`, `Group`, `WorkingDirectory`, `EnvironmentFile`, and `ExecStart` paths for the host:

```bash
sudo install -m 0644 deploy/systemd/raven-enrichment-worker.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/raven-enrichment-apply@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Operator workflow

Dry-run, limit 25:

```bash
sudo systemctl start raven-enrichment-worker.service
sudo journalctl -u raven-enrichment-worker.service -n 100 --no-pager
```

Explicit live apply, limit 10:

```bash
sudo systemctl start raven-enrichment-apply@10.service
sudo journalctl -u raven-enrichment-apply@10.service -n 100 --no-pager
```

Before an apply, review the dry-run output and target batch. After an apply, verify the row values and audit entries. Keep each apply bounded and inspect the result before running another batch.

## Validation

- Focused hosted unit tests cover exact identifier matching, NVD English description parsing, GHSA/OSV matching, safe reference URL handling, malformed feed payloads, audit-table absence, cooldown selection and timestamp normalization.
- The first live rollout should use a reviewed 10-CVE dry run.
- After apply, validate title/description/date/reference recovery and confirm graph/risk/approval table row counts are unchanged.
- Rate limits, source coverage, field correctness, host installation, and database integration remain go-live gates; a green unit suite alone is not a declaration of production readiness.
