#!/usr/bin/env bash
# Read-only acceptance check for EPIC-01 and EPIC-02. Changes nothing.
cd "${RAVEN_DIR:-$HOME/raven/raven}" || { echo "repo directory not found"; exit 1; }
p=0; f=0
q() { docker compose exec -T postgres psql -U raven raven -At -c "$1" 2>/dev/null | tr -d '[:space:]'; }
check() {  # description  actual  operator  threshold
  local a="$2" r
  # only a real number can pass: awk would compare text like "?" as a string and could pass it by accident
  if [[ "$a" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && awk -v a="$a" -v b="$4" "BEGIN{exit !(a $3 b)}"; then r=PASS; p=$((p+1)); else r=FAIL; f=$((f+1)); [[ "$a" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] || a="no-data"; fi
  printf "%-5s %-64s %-9s (need %s %s)\n" "$r" "$1" "$a" "$3" "$4"
}
info() { printf "INFO  %-64s %s\n" "$1" "$2"; }

echo "=== EPIC-01: resilient multi-source ingestion ==="
check "E1 sources registered with a trust score"                  "$(q "SELECT count(*) FROM sources WHERE enabled AND trust IS NOT NULL")" ">" 0
check "E1 pipeline moving: raw documents fetched in last 24h"     "$(q "SELECT count(*) FROM raw_documents WHERE fetched_at > now() - interval '24 hours'")" ">" 0
check "E1 pipeline moving: CVE rows updated in last 24h"          "$(q "SELECT count(*) FROM vulnerabilities WHERE normalized_at > now() - interval '24 hours'")" ">" 0
check "E1 enabled sources with no success in 3x their interval"   "$(q "SELECT count(*) FROM sources WHERE enabled AND parser NOT IN ('cmdb','telegram') AND (last_success IS NULL OR last_success < now() - 3 * poll_seconds * interval '1 second')")" "==" 0
check "E1 enabled sources stuck failing (5+ failures in a row)"   "$(q "SELECT count(*) FROM sources WHERE enabled AND consecutive_failures >= 5")" "==" 0
info  "E1 outage isolation: sources failing now / delivering in last 6h" "$(q "SELECT count(*) FROM sources WHERE enabled AND consecutive_failures > 0") / $(q "SELECT count(*) FROM sources WHERE last_success > now() - interval '6 hours'")"
check "E1 vendor PSIRT sources that really ingest (msrc, cisco)"  "$(q "SELECT count(*) FROM sources WHERE source_id IN ('msrc','cisco') AND accepted_records > 0")" "==" 2
check "E1 SBOM (CycloneDX/SPDX) ingestion code present"           "$(grep -rliE 'cyclonedx|spdx' services libs --include=*.py 2>/dev/null | wc -l)" ">=" 1
check "E1 bus-edge contract violations routed to quarantine"      "$(docker compose exec -T normalizer grep -c on_invalid /app/main.py 2>/dev/null | head -1)" ">=" 1
check "E1 distinct records rejected as active_content (suspect)"  "$(q "SELECT count(DISTINCT doc_id) FROM quarantine WHERE reason = 'active_content'")" "==" 0

echo "running the malformed-record harness in a container..."
H=$(docker run --rm -v "$PWD:/app" -w /app raven-base-cpu:1.0 sh -c "pip install -q pytest >/dev/null 2>&1; python -m pytest tests/test_ingest_gate.py -q -s 2>&1")
pct() { echo "$H" | grep "$1" | grep -oE "= [0-9.]+%" | grep -oE "[0-9.]+" | head -1; }
check "E1 malformed records leaking into normalization (%)"       "$(pct LEAKAGE)" "<" 1
check "E1 malformed records dropped with no quarantine row (%)"   "$(pct 'dropped silently')" "==" 0

echo; echo "=== EPIC-02: versioned security ontology ==="
check "E2 STIX/TAXII 2.1 objects or client in the code"           "$(grep -rliE 'taxii|stix2' services libs --include=*.py 2>/dev/null | wc -l)" ">=" 1
check "E2 revision-history table exists (append-only versions)"   "$(q "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND (table_name ILIKE '%revision%' OR table_name ILIKE '%history%' OR table_name ILIKE '%version%')")" ">=" 1
for col in "cvss_base > 0|CVSS score" "cardinality(cwe_ids) > 0|CWE ids" "cardinality(cpe_uris) > 0|CPE URIs" "cardinality(capec_ids) > 0|CAPEC ids"; do
  info "E2 share of CVE rows that carry: ${col##*|}" "$(q "SELECT round(100.0 * count(*) FILTER (WHERE ${col%%|*}) / count(*), 1) FROM vulnerabilities")%"
done

echo; echo "---- $p passed, $f failed ----"
