from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Every service reads the same environment contract."""

    model_config = SettingsConfigDict(env_prefix="RAVEN_", extra="ignore")

    env: str = "prod"
    service_name: str = "raven"
    log_level: str = "INFO"
    metrics_port: int = 9100

    # --- bus ---
    kafka_bootstrap: str = "redpanda:9092"
    kafka_group_prefix: str = "raven"

    # --- relational system of record ---
    pg_dsn: str = ""

    # --- graph ---
    neo4j_uri: str = "bolt://neo4j:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    # --- search / vectors / cache ---
    opensearch_url: str = "http://opensearch:9200"
    qdrant_url: str = "http://qdrant:6333"
    redis_url: str = "redis://redis:6379/0"

    # --- object storage (WORM raw zone) ---
    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "raven"
    minio_secret_key: str = ""
    minio_secure: bool = False
    raw_bucket: str = "raven-raw"

    # --- model plane ---
    vllm_base_url: str = "http://vllm:8000/v1"
    vllm_model: str = "Qwen/Qwen2.5-32B-Instruct-AWQ"
    verifier_base_url: str = "http://vllm:8000/v1"
    verifier_model: str = "Qwen/Qwen2.5-32B-Instruct-AWQ"
    embedding_model: str = "BAAI/bge-base-en-v1.5"
    classifier_model: str = "distilbert-base-uncased"
    hf_home: str = "/models"

    # --- decision thresholds ---
    autonomy_confidence_threshold: float = 0.85
    autonomy_max_blast_radius: int = 3
    abstain_confidence_floor: float = 0.55

    # --- feeds ---
    nvd_api_key: str = ""
    feed_lookback_days: int = 7
    crawl_interval_seconds: int = 3600

    # --- expanded source integrations ---
    github_token: str = ""          # raises GHSA REST rate limit + enables pagination
    otx_api_key: str = ""          # AlienVault OTX pulses (community threat intel)
    telegram_api_id: str = ""
    telegram_api_hash: str = ""
    telegram_session: str = ""      # StringSession, generated once out-of-band - see
                                     # services/telegram_watcher/main.py docstring
    telegram_channels: str = ""     # comma-separated channel usernames, no @


@lru_cache
def get_settings() -> Settings:
    return Settings()
