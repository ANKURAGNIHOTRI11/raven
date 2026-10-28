#!/usr/bin/env python3
"""Create a fresh local .env with unique credentials; never overwrite an existing file."""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / ".env.example"
OUTPUT = ROOT / ".env"
SECRET_KEYS = (
    "POSTGRES_PASSWORD",
    "RAVEN_NEO4J_PASSWORD",
    "RAVEN_MINIO_SECRET_KEY",
    "RAVEN_GRAFANA_PASSWORD",
    "RAVEN_API_TOKEN",
)


def parse_lines(text: str) -> list[tuple[str, str] | str]:
    rows: list[tuple[str, str] | str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            rows.append(line)
        else:
            key, value = line.split("=", 1)
            rows.append((key.strip(), value.strip()))
    return rows


def main() -> int:
    if OUTPUT.exists():
        print(".env already exists; leaving it unchanged.")
        print("Run 'make validate-env' to check it. No secrets were printed.")
        return 0
    if not TEMPLATE.is_file():
        print("ERROR: .env.example is missing.")
        return 2

    rows = parse_lines(TEMPLATE.read_text(encoding="utf-8"))
    values = {item[0]: item[1] for item in rows if isinstance(item, tuple)}
    for key in SECRET_KEYS:
        values[key] = secrets.token_hex(32)

    user = values.get("POSTGRES_USER", "raven")
    database = values.get("POSTGRES_DB", "raven")
    password = values["POSTGRES_PASSWORD"]
    values["RAVEN_PG_DSN"] = (
        f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@postgres:5432/{quote(database, safe='')}"
    )

    rendered = []
    for item in rows:
        if isinstance(item, tuple):
            key, _ = item
            rendered.append(f"{key}={values.get(key, '')}")
        else:
            rendered.append(item)
    data = "\n".join(rendered) + "\n"

    fd, temporary = tempfile.mkstemp(prefix=".env.", dir=ROOT, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, OUTPUT)
        os.chmod(OUTPUT, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

    print("Created .env with unique generated secrets (file mode 600).")
    print("Edit optional feed/model settings if needed, then run 'make validate-env'.")
    print("Secret values were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
