from urllib.parse import quote

from deploy.validate_env import SECRET_KEYS, validate_values


def valid_values():
    values = {key: f"{i:064x}" for i, key in enumerate(SECRET_KEYS, start=1)}
    values.update({
        "POSTGRES_USER": "raven",
        "POSTGRES_DB": "raven",
        "RAVEN_BIND_ADDRESS": "127.0.0.1",
    })
    values["RAVEN_PG_DSN"] = (
        f"postgresql://raven:{quote(values['POSTGRES_PASSWORD'], safe='')}"
        "@postgres:5432/raven"
    )
    return values


def test_valid_unique_secrets_pass():
    assert validate_values(valid_values()) == []


def test_placeholder_or_missing_secret_fails_without_echoing_value():
    values = valid_values()
    values["RAVEN_API_TOKEN"] = "CHANGE_ME_API_TOKEN"
    errors = validate_values(values)
    assert any("RAVEN_API_TOKEN" in error for error in errors)
    assert "CHANGE_ME_API_TOKEN" not in "\n".join(errors)


def test_reused_secret_fails():
    values = valid_values()
    values["RAVEN_API_TOKEN"] = values["POSTGRES_PASSWORD"]
    assert any("different value" in error for error in validate_values(values))


def test_non_ipv4_bind_address_fails():
    values = valid_values()
    values["RAVEN_BIND_ADDRESS"] = "not-an-address"
    assert any("RAVEN_BIND_ADDRESS" in error for error in validate_values(values))


def test_database_dsn_mismatch_fails():
    values = valid_values()
    values["RAVEN_PG_DSN"] = "postgresql://wrong:wrong@postgres:5432/raven"
    assert any("RAVEN_PG_DSN" in error for error in validate_values(values))
