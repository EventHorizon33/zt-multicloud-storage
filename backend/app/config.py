"""Environment-based configuration. No secret has a usable default: the app
refuses to start in production mode if required secrets are missing."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZT_", env_file=".env", extra="ignore")

    # --- general ---
    # Fail closed (finding M4): an unset ZT_ENV means production. Development
    # conveniences (auto-generated KMS root key, /docs, no HSTS) need an
    # explicit ZT_ENV=development or test.
    env: str = "production"                  # production | development | test
    data_dir: Path = Path("./data")
    database_url: str = ""                   # default: sqlite under data_dir (metadata)
    audit_database_url: str = ""             # default: separate sqlite file (ADR-0006)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    trust_forwarded_for: bool = False        # only enable behind a trusted proxy (ADR-0011)
    # Number of trusted proxies that APPEND to X-Forwarded-For in front of the
    # backend. The client IP is the entry this many positions from the right
    # of the joined header (all header lines, in order). Default 1.
    trusted_proxy_hops: int = 1
    # Optional: honour X-Forwarded-For only when the TCP peer is inside one of
    # these networks (the proxies). Empty = any peer (rely on the network setup).
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    # Bearer token for /metrics scrapers (constant-time compared). Unset: only
    # an authenticated admin may read /metrics. No peer address is trusted (L5).
    metrics_token: str | None = None
    log_level: str = "INFO"

    # --- bootstrap admin (optional; created at startup if set and absent) ---
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    # --- auth ---
    access_token_ttl_seconds: int = 300
    refresh_token_ttl_seconds: int = 8 * 3600
    session_absolute_ttl_seconds: int = 12 * 3600
    session_idle_ttl_seconds: int = 30 * 60
    token_issuer: str = "zt-multicloud-storage"
    token_audience: str = "zt-api"
    password_min_length: int = 12
    max_failed_logins: int = 5
    lockout_seconds: int = 15 * 60
    mfa_step_up_max_age_seconds: int = 10 * 60   # sensitive actions need MFA this fresh
    bind_session_to_ip: bool = False              # optional contextual check
    cookie_secure: bool = True                    # set False only for local http dev
    # UNC5537 lesson: a password alone must not be enough. Sessions without
    # MFA are restricted to MFA enrolment (PDP guard ``mfa-enrollment-required``).
    # Default of the runtime policy parameter of the same name (ADR-0010).
    require_mfa_for_login: bool = True
    # Trust-on-first-use window: a new account that has never had MFA may
    # enrol its first factor itself only within this many seconds of
    # registration. Afterwards it needs an admin-issued enrolment code (ADR-0010).
    mfa_self_enroll_window_seconds: int = 24 * 3600
    mfa_enrollment_code_ttl_seconds: int = 24 * 3600   # admin-issued, single use
    mfa_pending_enrollment_ttl_seconds: int = 15 * 60  # enrol -> activate must happen within this
    allow_self_registration: bool = True               # false: POST /api/auth/register -> 403

    # --- rate limiting (per client ip / per user, token bucket) ---
    rate_limit_login_per_minute: int = 10
    rate_limit_register_per_minute: int = 5
    rate_limit_upload_per_minute: int = 30
    rate_limit_download_per_minute: int = 60
    rate_limit_verify_per_minute: int = 6            # file verify/repair re-read every replica (L6)
    rate_limit_audit_export_per_minute: int = 6      # NDJSON export (L7)
    # Requests whose bearer token fails verification, per client network
    # (IPv4 /32, IPv6 /64). Over the limit -> 429 before any token crypto (M2).
    rate_limit_invalid_token_per_minute: int = 20

    # --- KMS ---
    kms_backend: str = "local"               # local | aws
    kms_keystore_path: Path | None = None    # default: data_dir/kms/keystore.json
    kms_root_key: str | None = None          # base64 32 bytes; REQUIRED outside test
    kms_root_key_file: Path | None = None    # alternative to env var (docker secret)
    aws_kms_key_id: str | None = None
    aws_kms_endpoint_url: str | None = None

    # --- chunking / crypto ---
    chunk_size_bytes: int = 1024 * 1024
    max_upload_bytes: int = 256 * 1024 * 1024

    # --- storage ---
    # comma separated provider instance names to enable; each needs its settings
    storage_providers: str = "aws-s3,azure-blob,gcs"
    replication_factor: int = 2
    min_write_replicas: int = 2              # fewer successful replicas => upload fails
    placement_strategy: str = "rotating"     # rotating | hash
    storage_timeout_seconds: float = 10.0
    retry_max_attempts: int = 4
    retry_base_delay_seconds: float = 0.2
    retry_max_delay_seconds: float = 3.0
    health_check_interval_seconds: float = 15.0
    enable_fault_injection: bool = False     # demo/testing only; never in production

    s3_bucket: str = "zt-chunks"
    s3_endpoint_url: str | None = None       # set for moto/MinIO; unset = real AWS
    s3_region: str = "us-east-1"
    s3_access_key_id: str | None = None
    s3_secret_access_key: str | None = None

    azure_container: str = "zt-chunks"
    azure_connection_string: str | None = None

    gcs_bucket: str = "zt-chunks"
    gcs_project: str | None = None
    gcs_endpoint_url: str | None = None      # set for emulator; unset = real GCS (ADC)

    # --- audit ---
    audit_checkpoint_every: int = 100        # events between automatic signed checkpoints
    audit_retention_days: int = 365
    audit_anchor_checkpoints: bool = True    # also write checkpoints to storage providers
    audit_ip_prefix_v4: int = 24             # generalise source ip before storing
    audit_ip_prefix_v6: int = 48

    # --- detection ---
    detect_window_seconds: int = 300
    detect_max_downloads_in_window: int = 20
    detect_max_download_bytes_in_window: int = 512 * 1024 * 1024
    detect_block_seconds: int = 600

    @model_validator(mode="after")
    def _derive(self) -> "Settings":
        self.data_dir = Path(self.data_dir)
        if not self.database_url:
            self.database_url = f"sqlite:///{self.data_dir / 'metadata.db'}"
        if not self.audit_database_url:
            self.audit_database_url = f"sqlite:///{self.data_dir / 'audit.db'}"
        if self.kms_keystore_path is None:
            self.kms_keystore_path = self.data_dir / "kms" / "keystore.json"
        if self.min_write_replicas > self.replication_factor:
            raise ValueError("min_write_replicas cannot exceed replication_factor")
        if self.replication_factor < 1:
            raise ValueError("replication_factor must be >= 1")
        if self.chunk_size_bytes < 1024:
            raise ValueError("chunk_size_bytes must be >= 1024")
        if self.env not in ("production", "development", "test"):
            raise ValueError("env must be one of production, development, test")
        if not 1 <= int(self.trusted_proxy_hops) <= 16:
            raise ValueError("trusted_proxy_hops must be between 1 and 16")
        import ipaddress
        for cidr in self.trusted_proxy_cidrs:
            try:
                ipaddress.ip_network(str(cidr).strip(), strict=False)
            except ValueError:
                raise ValueError("trusted_proxy_cidrs contains an invalid network") from None
        if self.metrics_token is not None and len(self.metrics_token) < 32:
            raise ValueError("metrics_token must be at least 32 characters")
        if self.env == "production":
            if self.enable_fault_injection:
                raise ValueError("fault injection cannot be enabled in production")
            if not self.cookie_secure:
                raise ValueError("cookie_secure must be true in production")
        return self

    @property
    def provider_names(self) -> list[str]:
        return [p.strip() for p in self.storage_providers.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
