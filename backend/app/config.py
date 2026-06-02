"""Application configuration for Sentinel-AI XDR."""
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Sentinel-AI XDR"
    app_env: str = "development"
    secret_key: str = "CHANGE-ME-IN-PRODUCTION-USE-32-CHAR-MINIMUM"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # MongoDB (primary database)
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "sentinel_xdr"

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:8501"

    mfa_issuer: str = "Sentinel-AI-XDR"
    ldap_enabled: bool = False
    ldap_server: str = ""
    ldap_base_dn: str = ""

    misp_url: str = ""
    misp_api_key: str = ""
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    greynoise_api_key: str = ""

    mlflow_tracking_uri: str = "http://localhost:5000"
    network_discovery_enabled: bool = True
    network_scan_subnet: str = "auto"
    packet_capture_interface: str = "auto"
    ids_mode: str = "monitor"
    ips_require_approval: bool = True

    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    collect_windows_events: bool = True
    collect_syslog: bool = True
    collect_endpoint: bool = True
    collect_network: bool = True

    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    password_min_length: int = 12

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
