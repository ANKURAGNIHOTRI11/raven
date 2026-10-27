from deploy.validate_env import SECRET_KEYS, validate_values


def valid_values():
    values = {key: f"{i:064x}" for i, key in enumerate(SECRET_KEYS, start=1)}
    values["RAVEN_BIND_ADDRESS"] = "127.0.0.1"
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
