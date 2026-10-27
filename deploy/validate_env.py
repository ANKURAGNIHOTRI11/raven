#!/usr/bin/env python3
"""Validate RAVEN's local .env without printing credential values."""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import quote

SECRET_KEYS = (
    "POSTGRES_PASSWORD",
    "RAVEN_NEO4J_PASSWORD",
    "RAVEN_MINIO_SECRET_KEY",
    "RAVEN_GRAFANA_PASSWORD",
    "RAVEN_API_TOKEN",
)
HEX_SECRET = re.compile(r"^[0-9a-fA-F]{64}$")
SIMPLE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def validate_values(values: dict[str, str]) -> list[str]:
    errors: list[str] = []
    secret_values: list[str] = []
    for key in SECRET_KEYS:
        value = values.get(key, "")
        if not HEX_SECRET.fullmatch(value):
            errors.append(
                f"{key} must be set to a unique 64-character hex value "
                "(generate one with: openssl rand -hex 32)."
            )
        else:
            secret_values.append(value.lower())

    if len(secret_values) == len(SECRET_KEYS) and len(secret_values) != len(set(secret_values)):
        errors.append("Each required secret must have a different value.")

    user = values.get("POSTGRES_USER", "")
    database = values.get("POSTGRES_DB", "")
    if not SIMPLE_IDENTIFIER.fullmatch(user):
        errors.append("POSTGRES_USER must be a simple SQL identifier.")
    if not SIMPLE_IDENTIFIER.fullmatch(database):
        errors.append("POSTGRES_DB must be a simple SQL identifier.")

    if HEX_SECRET.fullmatch(values.get("POSTGRES_PASSWORD", "")) and user and database:
        expected_dsn = (
            f"postgresql://{quote(user, safe='')}:{quote(values['POSTGRES_PASSWORD'], safe='')}"
            f"@postgres:5432/{quote(database, safe='')}"
        )
        if values.get("RAVEN_PG_DSN") != expected_dsn:
            errors.append("RAVEN_PG_DSN does not match the configured Postgres user/database/password.")

    bind_address = values.get("RAVEN_BIND_ADDRESS", "127.0.0.1")
    try:
        parsed_address = ipaddress.ip_address(bind_address)
        if not isinstance(parsed_address, ipaddress.IPv4Address):
            errors.append("RAVEN_BIND_ADDRESS must be an IPv4 address.")
    except ValueError:
        errors.append("RAVEN_BIND_ADDRESS must be a valid IPv4 address.")

    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    path = Path(args[0] if args else ".env")
    if not path.is_file():
        print(f"ERROR: {path} not found. Run 'make env' first.")
        return 2

    try:
        values = parse_env(path)
    except OSError:
        print(f"ERROR: Could not read {path}.")
        return 2

    errors = validate_values(values)
    if errors:
        print("RAVEN environment validation failed:")
        for error in errors:
            print(f"  - {error}")
        print("Credential values were not displayed.")
        return 1

    if not ipaddress.ip_address(values.get("RAVEN_BIND_ADDRESS", "127.0.0.1")).is_loopback:
        print("WARNING: RAVEN_BIND_ADDRESS is not loopback; published ports may be reachable on the network.")
    print(f"RAVEN environment validation passed for {path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
